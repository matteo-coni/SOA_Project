

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Syscall-table-discovery modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/reference-monitor modules
	
clean:
	make -C Syscall-table-discovery/ clean
	make -C reference-monitor/ clean

mount: 
	make -C Syscall-table-discovery/ mount
	make -C reference-monitor/ mount

unmount:
	rmmod the_usctm
	rmmod reference_monitor


#obj-m += reference_monitor.o
#obj-m += the_usctm.o


#the_rm-objs := reference-monitor/referenc_module.o reference_monitor.o
#the_usctm-objs := /Syscall-table-discovery/usctm.o /Syscall-table-discovery/lib/vtpmo.o reference_monitor.o

#all:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
#clean:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

