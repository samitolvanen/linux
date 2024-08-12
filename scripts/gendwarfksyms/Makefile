hostprogs-always-y += gendwarfksyms

gendwarfksyms-objs += gendwarfksyms.o
gendwarfksyms-objs += dwarf.o
gendwarfksyms-objs += symbols.o

HOST_EXTRACFLAGS := -I $(srctree)/tools/include
HOSTLDLIBS_gendwarfksyms := -ldw -lelf
