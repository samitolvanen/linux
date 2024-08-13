hostprogs-always-y += gendwarfksyms

gendwarfksyms-objs += gendwarfksyms.o
gendwarfksyms-objs += cache.o
gendwarfksyms-objs += crc32.o
gendwarfksyms-objs += die.o
gendwarfksyms-objs += dwarf.o
gendwarfksyms-objs += symbols.o
gendwarfksyms-objs += types.o

HOST_EXTRACFLAGS := -I $(srctree)/tools/include
HOSTLDLIBS_gendwarfksyms := -ldw -lelf
