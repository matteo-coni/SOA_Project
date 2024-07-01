/*
* 
* This is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* This module is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*  
* @brief Reference Monitor implementation for file protection
*
* @author Matteo Coni
*
* @date June 29, 2024
*/

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/unistd.h>


#include "../reference_monitor.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Coni");
MODULE_DESCRIPTION("Kernel Level Reference Monitor Module");

char password[PWD_LEN];
module_param_string(password, password, PWD_LEN, 0);

/* syscall table base address */
unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);


int init_module(void) {

    int ret;
    char *pwd_encrypted;

    ret = ref_monitor_initialize();
    if (ret != 0) {
                return ret;
        }

    reference_monitor.state = 0;

    INIT_LIST_HEAD(&reference_monitor.protected_paths)

    
    return 0;
    
}


void cleanup_module(void) {

   
        
}