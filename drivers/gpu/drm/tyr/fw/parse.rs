// SPDX-License-Identifier: GPL-2.0 or MIT

//! Code to parse the firmware binary.

use core::ops::Range;

use cursor::Cursor;
use kernel::alloc::KVec;
use kernel::bits::bit_u32;
use kernel::c_str;
use kernel::devres::Devres;
use kernel::io::mem::IoMem;
use kernel::prelude::*;
use kernel::str::CString;
use kernel::sync::Arc;
use kernel::sync::Mutex;

use crate::driver::TyrDevice;
use crate::fw::Firmware;
use crate::fw::CSF_MCU_SHARED_REGION_START;
use crate::gem;
use crate::gem::KernelVaPlacement;
use crate::gpu::GpuId;
use crate::gpu::GpuInfo;
use crate::mmu::vm;
use crate::mmu::vm::Vm;

mod cursor;

mod flags {
    use kernel::bits::bit_u32;
    use kernel::bits::genmask_u32;
    use kernel::prelude::*;

    use crate::impl_flags;

    impl_flags!(Flags, Flag, u32);

    const CACHE_MODE_MASK: Flags = Flags(genmask_u32(3..=4));

    impl Flags {
        pub(crate) fn cache_mode(&self) -> Flags {
            *self & CACHE_MODE_MASK
        }
    }

    impl TryFrom<u32> for Flags {
        type Error = Error;

        fn try_from(value: u32) -> Result<Self, Self::Error> {
            if value & valid_flags().0 != value {
                Err(EINVAL)
            } else {
                Ok(Self(value))
            }
        }
    }

    pub(crate) fn valid_flags() -> Flags {
        Flags::from(READ)
            | Flags::from(WRITE)
            | Flags::from(EXEC)
            | CACHE_MODE_MASK
            | Flags::from(PROT)
            | Flags::from(SHARED)
            | Flags::from(ZERO)
    }

    pub(crate) const READ: Flag = Flag(bit_u32(0));
    pub(crate) const WRITE: Flag = Flag(bit_u32(1));
    pub(crate) const EXEC: Flag = Flag(bit_u32(2));
    #[expect(unused)]
    pub(crate) const CACHE_MODE_NONE: Flag = Flag(0 << 3);
    pub(crate) const CACHE_MODE_CACHED: Flag = Flag(1 << 3);
    #[expect(unused)]
    pub(crate) const CACHE_MODE_UNCACHED_COHERENT: Flag = Flag(2 << 3);
    #[expect(unused)]
    pub(crate) const CACHE_MODE_CACHED_COHERENT: Flag = Flag(3 << 3);
    pub(crate) const PROT: Flag = Flag(bit_u32(5));
    pub(crate) const SHARED: Flag = Flag(bit_u32(30));
    pub(crate) const ZERO: Flag = Flag(bit_u32(31));
}

struct BuildInfoHeader(Range<u32>);

impl BuildInfoHeader {
    fn new(tdev: &TyrDevice, cursor: &mut Cursor<'_>) -> Result<Self> {
        let start = cursor.read_u32(tdev)?;

        Ok(Self(Range {
            start,
            end: start + cursor.read_u32(tdev)?,
        }))
    }

    fn start(&self) -> u32 {
        self.0.start
    }

    fn end(&self) -> u32 {
        self.0.end
    }
}

/// A parsed section of the firmware binary.
#[allow(dead_code)]
pub(crate) struct Section {
    /// Flags for this section.
    flags: flags::Flags,

    /// The name of the section in the binary, if any.
    name: Option<CString>,

    /// The raw parsed data for reset purposes.
    data: KVec<u8>,

    /// The BO that this section was loaded into.
    pub(super) mem: gem::ObjectRef,

    /// The VA range for this section.
    ///
    /// The MCU expects the firmware to be loaded at a specific addresses.
    pub(super) va: Range<u32>,

    /// The flags used to map this section.
    vm_map_flags: vm::map_flags::Flags,
}

impl Section {
    pub(super) fn is_shared(&self) -> bool {
        self.va.start == CSF_MCU_SHARED_REGION_START
            && self.flags.contains(flags::SHARED)
    }
}

/// The firmware header.
#[allow(dead_code)]
struct BinaryHeader {
    /// Magic value to check binary validity.
    magic: u32,

    /// Minor FW version.
    minor: u8,

    /// Major FW version.
    major: u8,

    /// Padding. Must be set to zero.
    _padding1: u16,

    /// FW Version hash
    version_hash: u32,

    /// Padding. Must be set to zero.
    _padding2: u32,

    /// FW binary size
    size: u32,
}

impl BinaryHeader {
    const FW_BINARY_MAGIC: u32 = 0xc3f13a6e;
    const FW_BINARY_MAJOR_MAX: u8 = 0;

    fn new(tdev: &TyrDevice, cursor: &mut Cursor<'_>) -> Result<Self> {
        let magic = cursor.read_u32(tdev)?;
        if magic != Self::FW_BINARY_MAGIC {
            dev_err!(tdev.as_ref(), "Invalid firmware magic");
            return Err(EINVAL);
        }

        let minor = cursor.read_u8(tdev)?;
        let major = cursor.read_u8(tdev)?;

        if major > Self::FW_BINARY_MAJOR_MAX {
            dev_err!(
                tdev.as_ref(),
                "Unsupported firmware binary header version {}.{} (expected {}.x)\n",
                major,
                minor,
                Self::FW_BINARY_MAJOR_MAX
            );
            return Err(EINVAL);
        }

        let padding1 = cursor.read_u16(tdev)?;
        let version_hash = cursor.read_u32(tdev)?;
        let padding2 = cursor.read_u32(tdev)?;
        let size = cursor.read_u32(tdev)?;

        if padding1 != 0 || padding2 != 0 {
            dev_err!(
                tdev.as_ref(),
                "Invalid firmware file: header padding is not zero"
            );
            return Err(EINVAL);
        }

        Ok(Self {
            magic,
            minor,
            major,
            _padding1: padding1,
            version_hash,
            _padding2: padding2,
            size,
        })
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum BinaryEntryType {
    /// Host <-> FW interface.
    Iface = 0,
    /// FW config.
    Config = 1,
    /// Unit tests.
    FutfTest = 2,
    /// Trace buffer interface.
    TraceBuffer = 3,
    /// Timeline metadata interface,
    TimelineMetadata = 4,
    /// Metadata about how the FW binary was built
    BuildInfoMetadata = 6,
}

impl TryFrom<u8> for BinaryEntryType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BinaryEntryType::Iface),
            1 => Ok(BinaryEntryType::Config),
            2 => Ok(BinaryEntryType::FutfTest),
            3 => Ok(BinaryEntryType::TraceBuffer),
            4 => Ok(BinaryEntryType::TimelineMetadata),
            6 => Ok(BinaryEntryType::BuildInfoMetadata),
            _ => Err(EINVAL),
        }
    }
}

#[derive(Debug)]
struct BinarySectionEntryHeader {
    /// Section flags
    flags: flags::Flags,
    /// MCU virtual range to map this binary section to.
    va: Range<u32>,
    /// References the data in the FW binary.
    data: Range<u32>,
}

impl BinarySectionEntryHeader {
    fn new(tdev: &TyrDevice, cursor: &mut Cursor<'_>) -> Result<Self> {
        let flags = cursor.read_u32(tdev)?;
        let flags = flags::Flags::try_from(flags)?;

        let va_start = cursor.read_u32(tdev)?;
        let va_end = cursor.read_u32(tdev)?;

        let va = va_start..va_end;

        if va.is_empty() {
            dev_err!(
                tdev.as_ref(),
                "Invalid firmware file: empty VA range at pos {}\n",
                cursor.pos(),
            );
            return Err(EINVAL);
        }

        let data_start = cursor.read_u32(tdev)?;
        let data_end = cursor.read_u32(tdev)?;
        let data = data_start..data_end;

        Ok(Self { flags, va, data })
    }
}

struct BinaryEntryHeader(u32);

impl BinaryEntryHeader {
    /// Raw, encoded entry type
    fn entry_type_raw(&self) -> u8 {
        (self.0 & 0xff) as u8
    }

    /// The entry type.
    fn entry_type(&self) -> Result<BinaryEntryType> {
        let v = self.entry_type_raw();
        BinaryEntryType::try_from(v)
    }

    /// Whether this entry is optional.
    fn optional(&self) -> bool {
        self.0 & bit_u32(31) != 0
    }

    /// The size of the entry.
    fn size(&self) -> u32 {
        self.0 >> 8 & 0xff
    }
}

struct BinaryEntrySection {
    hdr: BinaryEntryHeader,
    inner: Option<KBox<Section>>,
}

impl Firmware {
    /// Load the firmware
    fn load(
        tdev: &TyrDevice,
        gpu_info: &GpuInfo,
    ) -> Result<kernel::firmware::Firmware> {
        let gpu_id = GpuId::from(gpu_info.gpu_id);

        let fw_path = CString::try_from_fmt(fmt!(
            "arm/mali/arch{}.{}/mali_csffw.bin",
            gpu_id.arch_major,
            gpu_id.arch_minor
        ))?;

        Ok(kernel::firmware::Firmware::request(
            &fw_path,
            tdev.as_ref(),
        )?)
    }

    /// Parses the firmware sections from the binary.
    pub(super) fn read_sections(
        tdev: &TyrDevice,
        iomem: Arc<Devres<IoMem>>,
        gpu_info: &GpuInfo,
        vm: Arc<Mutex<Vm>>,
    ) -> Result<KVec<KBox<Section>>> {
        let fw = Self::load(tdev, gpu_info)?;

        let mut cursor = Cursor::new(fw.data());

        dev_dbg!(
            tdev.as_ref(),
            "Requested {} bytes of firmware successfully\n",
            fw.data().len()
        );

        let fw_bin_hdr = match BinaryHeader::new(tdev, &mut cursor) {
            Ok(fw_bin_hdr) => fw_bin_hdr,
            Err(e) => {
                dev_err!(
                    tdev.as_ref(),
                    "Invalid firmware file: {}",
                    e.to_errno()
                );
                return Err(e);
            }
        };

        if fw_bin_hdr.size > cursor.len() as u32 {
            dev_err!(tdev.as_ref(), "Firmware image is truncated");
            return Err(EINVAL);
        }

        let mut sections = KVec::new();

        while (cursor.pos() as u32) < fw_bin_hdr.size {
            let section = Self::read_entry(
                &mut cursor,
                tdev,
                iomem.clone(),
                &fw,
                vm.clone(),
            )?;
            if let Some(inner) = section.inner {
                sections.push(inner, GFP_KERNEL)?;
            }
        }

        Ok(sections)
    }

    fn read_entry(
        cursor: &mut Cursor<'_>,
        tdev: &TyrDevice,
        iomem: Arc<Devres<IoMem>>,
        fw: &kernel::firmware::Firmware,
        vm: Arc<Mutex<Vm>>,
    ) -> Result<BinaryEntrySection> {
        let section = BinaryEntrySection {
            hdr: BinaryEntryHeader(cursor.read_u32(tdev)?),
            inner: None,
        };

        if cursor.pos() % size_of::<u32>() != 0
            || section.hdr.size() as usize % size_of::<u32>() != 0
        {
            dev_err!(
                tdev.as_ref(),
                "Firmware entry isn't 32 bit aligned, offset={:#x} size={:#x}\n",
                cursor.pos() - size_of::<u32>(),
                section.hdr.size()
            );
            return Err(EINVAL);
        }

        let section_size =
            section.hdr.size() as usize - size_of::<BinaryEntryHeader>();
        let section = {
            let mut entry_cursor =
                cursor.view(cursor.pos()..cursor.pos() + section_size)?;

            match section.hdr.entry_type() {
                Ok(BinaryEntryType::Iface) => Ok(BinaryEntrySection {
                    hdr: section.hdr,
                    inner: Self::read_section(
                        tdev,
                        iomem,
                        &mut entry_cursor,
                        fw,
                        vm,
                    )?,
                }),

                Ok(BinaryEntryType::BuildInfoMetadata) => {
                    let _ = Self::read_build_info(tdev, &mut entry_cursor, fw);
                    Ok(section)
                }

                Ok(entry_type)
                    if matches!(
                        entry_type,
                        BinaryEntryType::Config
                            | BinaryEntryType::FutfTest
                            | BinaryEntryType::TraceBuffer
                            | BinaryEntryType::TimelineMetadata
                    ) =>
                {
                    Ok(section)
                }

                entry_type @ _ => {
                    if entry_type.is_err() || !section.hdr.optional() {
                        if !section.hdr.optional() {
                            dev_err!(
                                tdev.as_ref(),
                                "Failed to handle firmware entry type: {}\n",
                                entry_type.map_or(
                                    section.hdr.entry_type_raw(),
                                    |e| e as u8
                                )
                            );
                            Err(EINVAL)
                        } else {
                            dev_info!(
                                tdev.as_ref(),
                                "Unexpected firmware entry type: {}\n",
                                entry_type.map_or(
                                    section.hdr.entry_type_raw(),
                                    |e| e as u8
                                )
                            );
                            Ok(section)
                        }
                    } else {
                        dev_info!(
                            tdev.as_ref(),
                            "Skipping unsupported entry type: {}",
                            entry_type.unwrap() as u8
                        );
                        Ok(section)
                    }
                }
            }
        };

        if section.is_ok() {
            cursor.advance(section_size)?;
        }
        section
    }

    fn read_section(
        tdev: &TyrDevice,
        iomem: Arc<Devres<IoMem>>,
        cursor: &mut Cursor<'_>,
        fw: &kernel::firmware::Firmware,
        vm: Arc<Mutex<Vm>>,
    ) -> Result<Option<KBox<Section>>> {
        let hdr = BinarySectionEntryHeader::new(tdev, cursor)?;

        if hdr.data.end as usize > fw.size() {
            dev_err!(
                tdev.as_ref(),
                "Firmware corrupted, file truncated? data_end={:#x} fw size={:#x}\n",
                hdr.data.end,
                fw.size()
            );
            return Err(EINVAL);
        }

        if hdr.flags.contains(flags::PROT) {
            dev_warn!(
                tdev.as_ref(),
                "Firmware protected mode entry not supported, ignoring"
            );
            return Ok(None);
        }

        if hdr.va.start == CSF_MCU_SHARED_REGION_START
            && !hdr.flags.contains(flags::SHARED)
        {
            dev_err!(
                tdev.as_ref(),
                "Interface at 0x{:x} must be shared",
                CSF_MCU_SHARED_REGION_START
            );
            return Err(EINVAL);
        }

        let name_len = cursor.len() - cursor.pos();
        let name_bytes = cursor.read(tdev, name_len)?;

        let mut name = KVec::with_capacity(name_bytes.len() + 1, GFP_KERNEL)?;
        name.extend_from_slice(name_bytes, GFP_KERNEL)?;
        name.push(0, GFP_KERNEL)?;

        let name = CStr::from_bytes_with_nul(&name)
            .ok()
            .and_then(|name| CString::try_from(name).ok());

        let fw = fw.data();
        let section_start = hdr.data.start as usize;
        let section_end = hdr.data.end as usize;

        let mut data = KVec::new();
        data.extend_from_slice(&fw[section_start..section_end], GFP_KERNEL)?;

        let bo_len = (hdr.va.end - hdr.va.start) as usize;

        let cache_mode = hdr.flags.cache_mode();

        let mut vm_map_flags = vm::map_flags::Flags::empty();

        if !hdr.flags.contains(flags::WRITE) {
            vm_map_flags |= vm::map_flags::READONLY;
        }
        if !hdr.flags.contains(flags::EXEC) {
            vm_map_flags |= vm::map_flags::NOEXEC;
        }
        if cache_mode != flags::CACHE_MODE_CACHED.into() {
            vm_map_flags |= vm::map_flags::UNCACHED;
        }

        let mut mem = gem::new_kernel_object(
            tdev,
            iomem,
            vm,
            KernelVaPlacement::At(hdr.va.start as u64..hdr.va.end as u64),
            vm_map_flags,
        )?;

        let vmap = mem.vmap()?;
        let vmap = vmap.as_mut_slice();

        vmap[0..data.len()].copy_from_slice(&data);

        if hdr.flags.contains(flags::ZERO) {
            vmap[data.len()..].fill(0);
        }

        dev_info!(
            tdev.as_ref(),
            "Copied firmware data to BO {:p} of size {} with flags {}\n",
            &mem.gem,
            bo_len,
            vm_map_flags
        );

        Ok(Some(KBox::new(
            Section {
                flags: hdr.flags,
                name,
                data,
                mem,
                va: hdr.va,
                vm_map_flags,
            },
            GFP_KERNEL,
        )?))
    }

    fn read_build_info(
        tdev: &TyrDevice,
        cursor: &mut Cursor<'_>,
        fw: &kernel::firmware::Firmware,
    ) -> Result<()> {
        let meta = BuildInfoHeader::new(tdev, cursor)?;

        if meta.start() as usize > fw.size() || meta.end() as usize > fw.size()
        {
            dev_err!(tdev.as_ref(), "Firmware build info corrupted\n");
            return Err(EINVAL);
        }

        let header = b"git_sha: ";
        let range = meta.start() as usize..meta.start() as usize + header.len();

        if header != fw.data().get(range).ok_or(EINVAL)? {
            return Err(EINVAL);
        }

        let index = meta.end() as usize - 1;
        if *fw.data().get(index).ok_or(EINVAL)? != b'\0' {
            dev_warn!(
                tdev.as_ref(),
                "Firmware's git sha is not NULL terminated\n"
            );
            return Err(EINVAL);
        }

        let range = meta.start() as usize + header.len()..meta.end() as usize;
        dev_info!(
            tdev.as_ref(),
            "Firmware git sha: {}",
            CStr::from_bytes_with_nul(fw.data().get(range).ok_or(EINVAL)?)
                .unwrap_or(c_str!(""))
        );

        Ok(())
    }
}
