// SPDX-License-Identifier: GPL-2.0 or MIT

//! Firmware binary parser for Mali CSF (Command Stream Frontend) GPU.
//!
//! This module implements a parser for the Mali GPU firmware binary format. The firmware
//! file contains a header followed by a sequence of entries, each describing how to load
//! firmware sections into the MCU (Microcontroller Unit) memory. The parser extracts section metadata including:
//! - Virtual address ranges where sections should be mapped
//! - Data ranges (byte offsets) within the firmware binary
//! - Section flags (permissions, cache modes)

use core::{
    mem::size_of,
    ops::Range, //
};

use kernel::{
    bits::bit_u32,
    prelude::*,
    str::CString, //
};

use crate::{
    fw::{
        SectionFlag,
        SectionFlags,
        CSF_MCU_SHARED_REGION_START, //
    },
    vm::{
        VmFlag,
        VmMapFlags, //
    }, //
};

/// A parsed firmware section ready for loading into MCU memory.
///
/// Represents a single firmware section extracted from the firmware binary, containing
/// all information needed to map the section's data into the MCU's virtual address space.
pub(super) struct ParsedSection {
    /// Firmware bytes for this section, copied out of the source binary.
    pub(super) data: KVec<u8>,
    /// MCU virtual address range where this section should be mapped.
    pub(super) va: Range<u32>,
    /// Memory protection and caching flags for the mapping.
    pub(super) vm_map_flags: VmMapFlags,
}

/// A bare-bones `std::io::Cursor<[u8]>` clone to keep track of the current position in the firmware binary.
///
/// Provides methods to sequentially read primitive types and byte arrays from the firmware
/// binary while maintaining the current read position.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn pos(&self) -> usize {
        self.pos
    }

    /// Returns a view into the cursor's data.
    ///
    /// This spawns a new cursor, leaving the current cursor unchanged.
    fn view(&self, range: Range<usize>) -> Result<Cursor<'_>> {
        if range.start < self.pos || range.end > self.data.len() {
            pr_err!(
                "Invalid cursor range {:?} for data of length {}",
                range,
                self.data.len()
            );

            Err(EINVAL)
        } else {
            Ok(Self {
                data: &self.data[range],
                pos: 0,
            })
        }
    }

    /// Reads a slice of bytes from the current position and advances the cursor.
    ///
    /// Returns an error if the read would exceed the data bounds.
    fn read(&mut self, nbytes: usize) -> Result<&[u8]> {
        let start = self.pos;
        let end = start + nbytes;

        if end > self.data.len() {
            pr_err!(
                "Invalid firmware file: read of size {} at position {} is out of bounds",
                nbytes,
                start,
            );
            return Err(EINVAL);
        }

        self.pos += nbytes;
        Ok(&self.data[start..end])
    }

    /// Reads a little-endian `u8` from the current position and advances the cursor.
    fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read(size_of::<u8>())?;
        Ok(bytes[0])
    }

    /// Reads a little-endian `u16` from the current position and advances the cursor.
    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read(size_of::<u16>())?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a little-endian `u32` from the current position and advances the cursor.
    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read(size_of::<u32>())?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Advances the cursor position by the specified number of bytes.
    ///
    /// Returns an error if the advance would exceed the data bounds.
    fn advance(&mut self, nbytes: usize) -> Result {
        if self.pos + nbytes > self.data.len() {
            pr_err!(
                "Invalid firmware file: advance of size {} at position {} is out of bounds",
                nbytes,
                self.pos,
            );
            return Err(EINVAL);
        }
        self.pos += nbytes;
        Ok(())
    }
}

/// Parser for Mali CSF GPU firmware binaries.
///
/// Parses the firmware binary format, extracting section metadata including virtual
/// address ranges, data offsets, and memory protection flags needed to load firmware
/// into the MCU's memory.
pub(super) struct FwParser<'a> {
    cursor: Cursor<'a>,
}

impl<'a> FwParser<'a> {
    /// Creates a new firmware parser for the given firmware binary data.
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    /// Parses the firmware binary and returns a collection of parsed sections.
    ///
    /// This method validates the firmware header and iterates through all entries
    /// in the binary, extracting section information needed for loading.
    pub(super) fn parse(&mut self) -> Result<KVec<ParsedSection>> {
        let fw_header = self.parse_fw_header()?;

        let mut parsed_sections = KVec::new();
        while (self.cursor.pos() as u32) < fw_header.size {
            let entry_section = self.parse_entry()?;

            if let Some(inner) = entry_section.inner {
                parsed_sections.push(inner, GFP_KERNEL)?;
            }
        }

        // Validate that the firmware contains the required shared memory section.
        let has_shared_section = parsed_sections
            .iter()
            .any(|section| section.va.start == super::CSF_MCU_SHARED_REGION_START);

        if !has_shared_section {
            pr_err!(
                "No shared section found at 0x{:08x} in firmware\n",
                super::CSF_MCU_SHARED_REGION_START
            );
            return Err(EINVAL);
        }

        Ok(parsed_sections)
    }

    fn parse_fw_header(&mut self) -> Result<FirmwareHeader> {
        let fw_header: FirmwareHeader = match FirmwareHeader::new(&mut self.cursor) {
            Ok(fw_header) => fw_header,
            Err(e) => {
                pr_err!("Invalid firmware file: {}", e.to_errno());
                return Err(e);
            }
        };

        if fw_header.size > self.cursor.len() as u32 {
            pr_err!("Firmware image is truncated");
            return Err(EINVAL);
        }
        Ok(fw_header)
    }

    fn parse_entry(&mut self) -> Result<EntrySection> {
        let fw_data = self.cursor.data;
        let entry_section = EntrySection {
            entry_hdr: EntryHeader(self.cursor.read_u32()?),
            inner: None,
        };

        if self.cursor.pos() % size_of::<u32>() != 0
            || entry_section.entry_hdr.size() as usize % size_of::<u32>() != 0
        {
            pr_err!(
                "Firmware entry isn't 32 bit aligned, offset={:#x} size={:#x}\n",
                self.cursor.pos() - size_of::<u32>(),
                entry_section.entry_hdr.size()
            );
            return Err(EINVAL);
        }

        let section_hdr_size = entry_section.entry_hdr.size() as usize - size_of::<EntryHeader>();

        let entry_section = {
            let mut entry_cursor = self
                .cursor
                .view(self.cursor.pos()..self.cursor.pos() + section_hdr_size)?;

            match entry_section.entry_hdr.entry_type() {
                Ok(EntryType::Iface) => Ok(EntrySection {
                    entry_hdr: entry_section.entry_hdr,
                    inner: Self::parse_section_entry(&mut entry_cursor, fw_data)?,
                }),
                Ok(
                    EntryType::Config
                    | EntryType::FutfTest
                    | EntryType::TraceBuffer
                    | EntryType::TimelineMetadata
                    | EntryType::BuildInfoMetadata,
                ) => Ok(entry_section),

                entry_type => {
                    if entry_type.is_err() || !entry_section.entry_hdr.optional() {
                        if !entry_section.entry_hdr.optional() {
                            pr_err!(
                                "Failed to handle firmware entry type: {}\n",
                                entry_type
                                    .map_or(entry_section.entry_hdr.entry_type_raw(), |e| e as u8)
                            );
                            Err(EINVAL)
                        } else {
                            Ok(entry_section)
                        }
                    } else {
                        Ok(entry_section)
                    }
                }
            }
        };

        if entry_section.is_ok() {
            self.cursor.advance(section_hdr_size)?;
        }

        entry_section
    }

    fn copy_section_data(fw_data: &[u8], data_range: &Range<u32>) -> Result<KVec<u8>> {
        let start = data_range.start as usize;
        let end = data_range.end as usize;
        let bytes = fw_data.get(start..end).ok_or_else(|| {
            pr_err!(
                "Firmware corrupted, section data range [0x{:x}..0x{:x}) is out of bounds\n",
                data_range.start,
                data_range.end,
            );
            EINVAL
        })?;

        let mut data = KVec::new();
        data.extend_from_slice(bytes, GFP_KERNEL)?;
        Ok(data)
    }

    fn parse_section_entry(entry_cursor: &mut Cursor<'_>, fw_data: &[u8]) -> Result<Option<ParsedSection>> {
        let section_hdr: SectionHeader = SectionHeader::new(entry_cursor)?;

        if section_hdr.data.end < section_hdr.data.start {
            pr_err!(
                "Firmware corrupted, data.end < data.start (0x{:x} < 0x{:x})\n",
                section_hdr.data.end,
                section_hdr.data.start
            );
            return Err(EINVAL);
        }

        if section_hdr.va.end < section_hdr.va.start {
            pr_err!(
                "Firmware corrupted, section_hdr.va.end < section_hdr.va.start (0x{:x} < 0x{:x})\n",
                section_hdr.va.end,
                section_hdr.va.start
            );
            return Err(EINVAL);
        }

        if section_hdr.section_flags.contains(SectionFlag::Prot) {
            pr_info!("Firmware protected mode entry not supported, ignoring");
            return Ok(None);
        }

        if section_hdr.va.start == CSF_MCU_SHARED_REGION_START
            && !section_hdr.section_flags.contains(SectionFlag::Shared)
        {
            pr_err!(
                "Interface at 0x{:x} must be shared",
                CSF_MCU_SHARED_REGION_START
            );
            return Err(EINVAL);
        }

        let name_len = entry_cursor.len() - entry_cursor.pos();
        let name_bytes = entry_cursor.read(name_len)?;

        let mut name = KVec::with_capacity(name_bytes.len() + 1, GFP_KERNEL)?;
        name.extend_from_slice(name_bytes, GFP_KERNEL)?;
        name.push(0, GFP_KERNEL)?;

        let _name = CStr::from_bytes_with_nul(&name)
            .ok()
            .and_then(|name| CString::try_from(name).ok());

        let cache_mode = section_hdr.section_flags.cache_mode();
        let mut vm_map_flags = VmMapFlags::empty();

        if !section_hdr.section_flags.contains(SectionFlag::Write) {
            vm_map_flags |= VmFlag::Readonly;
        }
        if !section_hdr.section_flags.contains(SectionFlag::Exec) {
            vm_map_flags |= VmFlag::Noexec;
        }
        if cache_mode != SectionFlag::CacheModeCached.into() {
            vm_map_flags |= VmFlag::Uncached;
        }

        let data = Self::copy_section_data(fw_data, &section_hdr.data)?;

        Ok(Some(ParsedSection {
            data,
            va: section_hdr.va,
            vm_map_flags,
        }))
    }
}

/// Firmware binary header containing version and size information.
///
/// The header is located at the beginning of the firmware binary and contains
/// a magic value for validation, version information, and the total size of
/// all structured headers that follow.
#[expect(dead_code)]
struct FirmwareHeader {
    /// Magic value to check binary validity.
    magic: u32,

    /// Minor firmware version.
    minor: u8,

    /// Major firmware version.
    major: u8,

    /// Padding. Must be set to zero.
    _padding1: u16,

    /// Firmware version hash.
    version_hash: u32,

    /// Padding. Must be set to zero.
    _padding2: u32,

    /// Total size of all the structured data headers at beginning of firmware binary.
    size: u32,
}

impl FirmwareHeader {
    const FW_BINARY_MAGIC: u32 = 0xc3f13a6e;
    const FW_BINARY_MAJOR_MAX: u8 = 0;

    /// Reads and validates a firmware header from the cursor.
    ///
    /// Verifies the magic value, version compatibility, and padding fields.
    fn new(cursor: &mut Cursor<'_>) -> Result<Self> {
        let magic = cursor.read_u32()?;
        if magic != Self::FW_BINARY_MAGIC {
            pr_err!("Invalid firmware magic");
            return Err(EINVAL);
        }

        let minor = cursor.read_u8()?;
        let major = cursor.read_u8()?;

        if major > Self::FW_BINARY_MAJOR_MAX {
            pr_err!(
                "Unsupported firmware binary header version {}.{} (expected {}.x)\n",
                major,
                minor,
                Self::FW_BINARY_MAJOR_MAX
            );
            return Err(EINVAL);
        }

        let padding1 = cursor.read_u16()?;
        let version_hash = cursor.read_u32()?;
        let padding2 = cursor.read_u32()?;
        let size = cursor.read_u32()?;

        if padding1 != 0 || padding2 != 0 {
            pr_err!("Invalid firmware file: header padding is not zero");
            return Err(EINVAL);
        }

        let fw_header = Self {
            magic,
            minor,
            major,
            _padding1: padding1,
            version_hash,
            _padding2: padding2,
            size,
        };

        Ok(fw_header)
    }
}

/// Firmware section header for loading binary sections into MCU memory.
#[derive(Debug)]
struct SectionHeader {
    section_flags: SectionFlags,
    /// MCU virtual range to map this binary section to.
    va: Range<u32>,
    /// References the data in the FW binary.
    data: Range<u32>,
}

impl SectionHeader {
    /// Reads and validates a section header from the cursor.
    ///
    /// Parses section flags, virtual address range, and data range from the firmware binary.
    fn new(cursor: &mut Cursor<'_>) -> Result<Self> {
        let section_flags = cursor.read_u32()?;
        let section_flags = SectionFlags::try_from(section_flags)?;

        let va_start = cursor.read_u32()?;
        let va_end = cursor.read_u32()?;

        let va = va_start..va_end;

        if va.is_empty() {
            pr_err!(
                "Invalid firmware file: empty VA range at pos {}\n",
                cursor.pos(),
            );
            return Err(EINVAL);
        }

        let data_start = cursor.read_u32()?;
        let data_end = cursor.read_u32()?;
        let data = data_start..data_end;

        Ok(Self {
            section_flags,
            va,
            data,
        })
    }
}

/// A firmware entry containing a header and optional parsed section data.
///
/// Represents a single entry in the firmware binary, which may contain loadable
/// section data or metadata that doesn't require loading.
struct EntrySection {
    entry_hdr: EntryHeader,
    inner: Option<ParsedSection>,
}

/// Header for a firmware entry, packed into a single u32.
///
/// The entry header encodes the entry type, size, and optional flag in a
/// 32-bit value with the following layout:
/// - Bits 0-7: Entry type
/// - Bits 8-15: Size in bytes
/// - Bit 31: Optional flag
struct EntryHeader(u32);

impl EntryHeader {
    fn entry_type_raw(&self) -> u8 {
        (self.0 & 0xff) as u8
    }

    fn entry_type(&self) -> Result<EntryType> {
        let v = self.entry_type_raw();
        EntryType::try_from(v)
    }

    fn optional(&self) -> bool {
        self.0 & bit_u32(31) != 0
    }

    fn size(&self) -> u32 {
        self.0 >> 8 & 0xff
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum EntryType {
    /// Host <-> FW interface.
    Iface = 0,
    /// FW config.
    Config = 1,
    /// Unit tests.
    FutfTest = 2,
    /// Trace buffer interface.
    TraceBuffer = 3,
    /// Timeline metadata interface.
    TimelineMetadata = 4,
    /// Metadata about how the FW binary was built.
    BuildInfoMetadata = 6,
}

impl TryFrom<u8> for EntryType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EntryType::Iface),
            1 => Ok(EntryType::Config),
            2 => Ok(EntryType::FutfTest),
            3 => Ok(EntryType::TraceBuffer),
            4 => Ok(EntryType::TimelineMetadata),
            6 => Ok(EntryType::BuildInfoMetadata),
            _ => Err(EINVAL),
        }
    }
}
