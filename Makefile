#obj-m += the_rm.o
obj-m += the_usctm.o


#the_rm-objs := reference-monitor/rm_module.o reference_monitor.o
the_usctm-objs := /Syscall-table-discovery/usctm.o /Syscall-table-discovery/lib/vtpmo.o #reference_monitor.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

