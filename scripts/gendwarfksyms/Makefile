hostprogs-always-y += gendwarfksyms

gendwarfksyms-objs += gendwarfksyms.o
gendwarfksyms-objs += symbols.o
gendwarfksyms-objs += types.o

HOST_EXTRACFLAGS := -I $(srctree)/tools/include
HOSTLDLIBS_gendwarfksyms := -ldw -lelf
