obj-m += the_reference_monitor.o
the_reference_monitor-objs := reference_monitor.o utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount: 
	@read -p "Select a password: " password; \
	sudo insmod the_reference_monitor.ko syscall_table_addr=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) free_entries=$$(sudo cat /sys/module/the_usctm/parameters/free_entries) password="$$password"

#@stty -echo
#@read -p "Select a password: " password; echo
#	@stty echo
#	@if [ ! -f /sys/module/the_usctm/parameters/sys_call_table_address ]; then \
		echo "Error: sys_call_table_address not found. Is the_usctm module loaded?"; \
		exit 1; \
	fi
#	@syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) && \
#	sudo insmod reference_monitor.ko the_syscall_table=$$syscall_table password="$$password"