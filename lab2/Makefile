
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all:
	make -C ../dist/modulebuild M=$(PWD) modules

clean:
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp cryptomod.ko ../rootfs/modules

build:
	cp ../rootfs/modules/cryptomod.ko ../test/rootfs/modules/cryptomod.ko
	cd ../test && find . | cpio -o -H newc | bzip2 > ../dist/rootfs.cpio.bz2
	cd .. && ./qemu.sh
