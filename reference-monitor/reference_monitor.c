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
#define MODNAME "REFERENCE MONITOR"

#include "reference_monitor.h"

#include <linux/module.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Coni");
MODULE_DESCRIPTION("Kernel Level Reference Monitor Module");

struct reference_monitor reference_monitor;

static long syscall_table_addr = 0x0;
module_param(syscall_table_addr, ulong, 0644);
MODULE_PARM_DESC(sys_call_table, "Syscall_table address parameter"); //modifica desc

static char *password = NULL;
module_param(password, charp, 0000);
MODULE_PARM_DESC(password, "Ref_monitor password parameter");

static int free_entries[15];
module_param_array(free_entries,int,NULL,0660);
MODULE_PARM_DESC(free_entries, "Free entry of syscall table");

unsigned long sys_ni_syscall_address;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0, 0x0, 0x0};

/* system call switch_state reference monitor*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2,_switch_state, enum State, state, char* , password){
#else
asmlinkage int sys_switch_state(enum state, char __user* pw, int len){
#endif

    //dummy: implementa la system call per lo switch dello stato
    return 0; //ok
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _add_protected_paths, char *, path, char* , password) {
#else 
asmlinkage long sys_addd_protected_paths(char *rel_path) {
#endif

    //dummy: implementa aggiunta path alla lista protected_paths
    return 0; //ok
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _rm_protected_paths, char *, path, char* , password) {
#else 
asmlinkage long sys_rm_protected_pathss(char *rel_path) {
#endif

    //dummy: implementa rimozione path dalla lista protected_paths
    return 0; //ok
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _print_protected_paths, char*, output_buff, char*, password){
#else
asmlinkage int sys_print_protected_paths;(char __user * pw, int pw_size){
#endif

    //dummy: implementa print lista protected_paths
    return 0; //ok
}





#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_switch_state = (unsigned long)__x64_sys_switch_state;    
long sys_add_protected_paths = (unsigned long) __x64_sys_add_protected_paths;
long sys_rm_protected_paths = (unsigned long) __x64_sys_rm_protected_paths;
long sys_print_protected_paths = (unsigned long) __x64_sys_print_protected_paths;
#else
#endif



int inizialize_syscall(void){

    if(syscall_table_addr == 0x0){
        printk("%s: Syscall table address = 0x0", MODNAME);
        return -1;
    }

    printk(KERN_INFO "Syscall table address: 0x%lx\n", syscall_table_addr);

    /*
    - switch_state
    - add_protected_paths
    - rm_protected_paths
    - print_protected_paths
    */
    
    new_sys_call_array[0] = (unsigned long)sys_switch_state;
    new_sys_call_array[1] = (unsigned long)sys_add_protected_paths;
    new_sys_call_array[2] = (unsigned long)sys_rm_protected_paths;
    new_sys_call_array[3] = (unsigned long)sys_print_protected_paths;

    printk(KERN_INFO "Free entries syscall = ???");
    int i;
    for(i=0; i<15; i++){
        printk(KERN_INFO "Free entries syscall array[%d] = %d\n", i, free_entries[i]);
    }

    return 0;
}

int ref_monitor_initialize(void){
    
    reference_monitor.state = OFF; //State 0 == OFF

    INIT_LIST_HEAD(&reference_monitor.protected_paths);
    spin_lock_init(&reference_monitor.rf_lock);



    return 0;
}



int init_module(void) {
    int ret;
    char *pwd_encrypted = NULL;;

    printk(KERN_INFO "Initializing reference monitor\n");
    //printk(KERN_INFO "password = %s\n", password);

    /*add new syscall*/
    ret = inizialize_syscall();
    if (ret != 0){
        return ret;
    }
    
    ret = ref_monitor_initialize();
    if (ret != 0) {
                return ret;
        }

    if(!password || strlen(password)==0){
        printk(KERN_ERR "No pwd reference monitor provided\n");
        return -1;
    }

    pwd_encrypted = get_pwd_encrypted(password); //funzione ok ma non ritorna correttammente il valore
    if (!pwd_encrypted) {
        printk(KERN_ERR "Failed to encrypt password\n");
        return -ENOMEM;
    }
    
    
    reference_monitor.password = pwd_encrypted;    
    printk(KERN_INFO "pwd_encrypted ref monitor = %s\n", reference_monitor.password); //pwd ok

    printk(KERN_INFO "Reference monitor initialized successfully\n");
    
    return 0;
}


void cleanup_module(void) {


    //dummy
   
    return;
}