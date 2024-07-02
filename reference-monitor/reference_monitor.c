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
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/unistd.h>


#include "reference_monitor.h"
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Coni");
MODULE_DESCRIPTION("Kernel Level Reference Monitor Module");

struct reference_monitor reference_monitor;

char password[PWD_LEN];
module_param_string(password, password, PWD_LEN, 0);

/* syscall table base address */
unsigned long the_syscall_table = 0x0;
//module_param(the_syscall_table, ulong, 0660);

//char *get_pwd_encrypted(char *pwd);


int ref_monitor_initialize(void){
    if(!password || strlen(password)==0){
        printk("%s, no pwd reference monitor\n");
        return -1;
    }

    reference_monitor.state = 0; //State 0 == OFF

    INIT_LIST_HEAD(&reference_monitor.protected_paths);
    spin_lock_init(&reference_monitor.rf_lock);



    return 0;
}


int init_module(void) {

    int ret;
    char *pwd_encrypted;

    ret = ref_monitor_initialize();
    if (ret != 0) {
                return ret;
        }

    pwd_encrypted = get_pwd_encrypted(password);
    reference_monitor.password = pwd_encrypted;
    
    return 0;
    
}


void cleanup_module(void) {

   
    return;
}