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

#include "reference_monitor.h"

#include <linux/module.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Coni");
MODULE_DESCRIPTION("Kernel Level Reference Monitor Module");

struct reference_monitor reference_monitor;

/* password param for reference monitor
static char *password;
module_param(password, charp, 0000);
MODULE_PARM_DESC(password, "Password for the reference monitor");

/* syscall table base address 
static unsigned long the_syscall_table;
module_param(the_syscall_table, ulong, 0644);
MODULE_PARM_DESC(the_syscall_table, "Syscall table base address");
*/

static long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0644);
MODULE_PARM_DESC(sys_call_table, "Syscall_table address parameter"); //modifica desc

static char *password = NULL;
module_param(password, charp, 0000);
MODULE_PARM_DESC(password, "Ref_monitor password parameter");




int ref_monitor_initialize(void){
    
    reference_monitor.state = 0; //State 0 == OFF



    INIT_LIST_HEAD(&reference_monitor.protected_paths);
    spin_lock_init(&reference_monitor.rf_lock);



    return 0;
}


/*int init_module(void) {

    int ret;
    char *pwd_encrypted;

    

    ret = ref_monitor_initialize();
    if (ret != 0) {
                return ret;
        }

    pwd_encrypted = get_pwd_encrypted(password);
    if (!pwd_encrypted) {
        printk(KERN_ERR "Failed to encrypt password\n");
        return -ENOMEM;
    }
    
    reference_monitor.password = pwd_encrypted;
    
    printk(KERN_INFO "Reference monitor initialized successfully\n");
    
    return 0;
    
}*/

int init_module(void) {
    int ret;
    char *pwd_encrypted;

    printk(KERN_INFO "Initializing reference monitor\n");
    printk(KERN_INFO "Syscall table address: 0x%lx\n", the_syscall_table);
    //printk(KERN_INFO "password = %s\n", password);
    
    ret = ref_monitor_initialize();
    if (ret != 0) {
                return ret;
        }

    if(!password || strlen(password)==0){
        printk(KERN_ERR "No pwd reference monitor provided\n");
        return -1;
    }

    pwd_encrypted = get_pwd_encrypted(password);
    if (!pwd_encrypted) {
        printk(KERN_ERR "Failed to encrypt password\n");
        return -ENOMEM;
    }
    
    reference_monitor.password = pwd_encrypted;
    printk(KERN_INFO "pwd_encrypted = \n", pwd_encrypted);
    
    printk(KERN_INFO "Reference monitor initialized successfully\n");
    
    return 0;
}


void cleanup_module(void) {

    //dummy
   
    return;
}