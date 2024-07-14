

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Syscall-table-discovery modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/reference-monitor modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/singlefile-FS modules
	gcc -o user.o user.c
	gcc -o test_write.o test_write.c
	
clean:
	make -C Syscall-table-discovery/ clean
	make -C reference-monitor/ clean
	make -C singlefile-FS/ clean

mount:
	make -C singlefile-FS/ load-FS-driver
	make -C singlefile-FS/ create-fs
	make -C singlefile-FS/ mount-fs
	make -C Syscall-table-discovery/ mount
	make -C reference-monitor/ mount

unmount:
	sudo rmmod the_usctm
	sudo rmmod the_reference_monitor
	sudo make -C singlefile-FS/ umount-fs
	sudo rmmod singlefilefs


