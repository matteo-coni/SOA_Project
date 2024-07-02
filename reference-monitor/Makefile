obj-m += reference_monitor.o
the_rm-objs := reference_monitor.o utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount: 
	@read -p "Select a password: " password; \
	sudo insmod reference_monitor.ko the_syscall_table=$$(cat /sys/module/the_usctm/parameters/sys_call_table_address) password="$$password"