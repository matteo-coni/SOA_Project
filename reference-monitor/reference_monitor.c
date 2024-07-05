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
unsigned long cr0;

unsigned long *hack_ni_syscall; //prova

static long syscall_table_addr = 0x0;
module_param(syscall_table_addr, ulong, 0644);
MODULE_PARM_DESC(syscall_table_addr, "Syscall_table address parameter"); //modifica desc

static char *password = NULL;
module_param(password, charp, 0000);
MODULE_PARM_DESC(password, "Ref_monitor password parameter");

static int free_entries[15];
module_param_array(free_entries,int,NULL,0660);
MODULE_PARM_DESC(free_entries, "Free entry of syscall table");

unsigned long sys_ni_syscall_address;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0, 0x0, 0x0};

ino_t get_inode_from_path(const char *path){

    struct path file_path;
    int ret;
    ino_t inode;

    ret = kern_path(path, LOOKUP_FOLLOW, &file_path);
    if (ret){
        printk("%s: Error during get kernel_path from path");
        return -EINVAL;
    }
    // ottieni info sull'inode
    inode = file_path.dentry->d_inode->i_ino;
    
    path_put(&file_path);

    return inode;
}


int file_in_protected_paths_list(char *filename_path){

    int ret = 0;
    struct protected_paths_entry *entry, *tmp;
    ino_t inode_number;
    inode_number = get_inode_from_path(filename_path); //funzione oppure 
    if (inode_number == 0){
        //not valid path
        return 0;
    }

    printk("SONO DOPO La GET INODE");

    rcu_read_lock();
    list_for_each_entry_safe(entry, tmp, &reference_monitor.protected_paths, list){
        if (entry->inode_n == inode_number) {
            ret = 1;
            goto exit;       
        }
    }
    exit:
    rcu_read_unlock();

    // path isn't in protected_paths lists

    return ret;
}

/* system call SWITCH_STATE reference monitor */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2,_switch_state, char*, state, char*, password){
#else
asmlinkage int sys_switch_state(char* state, char __user* pw){
#endif*/

    char* kernel_pwd;
    char* kernel_state;
    printk("OKKKOOKOKOK iniziale");

    /* check if user is root EUID 0 */
    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)){ 
        printk(KERN_INFO "Only root user can change the status");
        return -EPERM;
    }

    printk("OKKKOOKOKOK");

    /* kmalloc pwd in kernel space */
    kernel_pwd = kmalloc(PWD_LEN, GFP_KERNEL);
	if (!kernel_pwd){
		printk("%s: Error kernel password allocation", MODNAME);
        	return -ENOMEM; 
		}
	printk("OKKKOOKOKOK 1111111111111");

	// Copy pwd from user space
	if (copy_from_user(kernel_pwd, password, PWD_LEN)) {
		printk("%s: Error during password copy from user",MODNAME);
		kfree(kernel_pwd);
		return -EFAULT;
	}

    printk("OKKKOOKOKOK 2222222222222");
    /* check if insert pwd is valid */
    if (strcmp(reference_monitor.password, get_pwd_encrypted(kernel_pwd)) != 0){
        printk("%s: Invalid password, change state not allowed", MODNAME);
        kfree(kernel_pwd);
        return -EACCES;
    }
    printk("OKKKOOKOKOK post check pwd");
    kfree(kernel_pwd);

    kernel_state = kmalloc(20, GFP_KERNEL);
	if (!state){
		printk("%s: Error kernel stateallocation", MODNAME);
        	return -ENOMEM; 
		}
	

	// Copy pwd from user space
	if (copy_from_user(kernel_state, state, PWD_LEN)) {
		printk("%s: Error during state copy from user",MODNAME);
		kfree(kernel_state);
		return -EFAULT;
	}
    printk("prova state kernel: %s", kernel_state);
    //spin_lock(&reference_monitor.rf_lock);
    
    if(strcmp(kernel_state, "ON")==0){
        
        printk("SONO IN IF ON ");
        reference_monitor.state = ON;
        printk("%s: Switching rm state to ON", MODNAME);
        
    } else if(strcmp(kernel_state, "OFF") == 0){
        
        printk("SONO IN IF OFF ");
        reference_monitor.state = OFF;
        printk("%s: Switching rm state to OFF", MODNAME);

    } else if(strcmp(kernel_state, "REC_OFF") == 0){

        printk("SONO IN IF REC_OFF ");
        reference_monitor.state = REC_OFF;
        printk("%s: Switching rm state to REC_OFF", MODNAME);

    } else if(strcmp(kernel_state, "REC_ON") == 0){
        printk("SONO IN IF REC_ON ") ;
        reference_monitor.state = REC_ON;
        printk("%s: Switching rm state to REC_ON", MODNAME);

    } else {
        printk("SONO nell'ELSE ") ;
    }
    printk("OKKKOOKOKOK 88888888");
    
    kfree(kernel_state);

    return 0; //ok
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _add_protected_paths, char *, path, char* , password) {
#else 
asmlinkage long sys_addd_protected_paths(char *path, char* password) {
#endif

    char* kernel_pwd;
    char* kernel_path;
    struct protected_paths_entry *entry_list;

    printk("OKKKOOKOKOK INIZIALE ADD");

    /* check if user is root EUID 0 */
    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)){ 
        printk(KERN_INFO "Only root user can change the status");
        return -EPERM;
    }

    printk("OKKKOOKOKOK");

    /* kmalloc pwd in kernel space */
    kernel_pwd = kmalloc(PWD_LEN, GFP_KERNEL);
	if (!kernel_pwd){
		printk("%s: Error kernel password allocation", MODNAME);
        	return -ENOMEM; 
		}

    printk("OKKKOOKOKOK 222222");
			
	// Copy pwd from user space
	if (copy_from_user(kernel_pwd, password, PWD_LEN)) {
		printk("%s: Error during password copy from user",MODNAME);
		kfree(kernel_pwd);
		return -EFAULT;
	}

    printk("OKKKOOKOKOK 333333333333333");

    /* check if insert pwd is valid*/
    if (strcmp(reference_monitor.password, get_pwd_encrypted(kernel_pwd)) != 0){
        printk("%s: Invalid password, change state not allowed", MODNAME);
        kfree(kernel_pwd);
        return -EACCES;
    }

    printk("OKKKOOKOKOK 444444444444444");

    kfree(kernel_pwd);

    /* add new path in list is allowed only in REC_ON or REC_OFF */
    if (reference_monitor.state == ON || reference_monitor.state == OFF){
        printk("%s: state is %s, it's not allowed to add a new path in protected_paths list", MODNAME, reference_monitor.state);
        return -EPERM;
    }

    kernel_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kernel_path)
		return -ENOMEM; 

	/* Copy the path from user space, PATH_MAX is 4096, max path size in kernel  */
	if (copy_from_user(kernel_path, path, PATH_MAX)) {
		kfree(kernel_path);
		return -EFAULT;
	}
    
    if (file_in_protected_paths_list(kernel_path)){
        printk("%s: Path %s is already in protected_paths list\n", MODNAME, kernel_path);
        return -EINVAL;
    }
    printk("FIN QUI OK 2");
    /* ADD FILE IN LIST */
    entry_list = kmalloc(sizeof(struct protected_paths_entry), GFP_KERNEL);
    entry_list->path = kstrdup(kernel_path, GFP_KERNEL);
    printk("FIN QUI OK 3");
    //entry_list->inode_n = get_inode_from_path(kernel_path); //TODO: RISOLVI QUA

    printk("FIN QUI OK 4");
    
    spin_lock(&reference_monitor.rf_lock);

    // Insert the new entry into the list under RCU protection
    rcu_read_lock();
    list_add_rcu(&entry_list->list, &reference_monitor.protected_paths);
    rcu_read_unlock();

    spin_unlock(&reference_monitor.rf_lock);

    printk("%s: path %s successfully added to protected_paths list", MODNAME, path);

    return 0; //ok
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _rm_protected_paths, char *, path, char* , password) {
#else 
asmlinkage long sys_rm_protected_paths(char *rel_path) {
#endif

    char* kernel_pwd;
    char* kernel_path;

    printk("STO IN REMOVE SYS");
    
    struct protected_paths_entry *entry_list, *tmp; //entry_list is an entry of list
    ino_t inode_number;

    /* check if user is root EUID 0 */
    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)){ 
        printk(KERN_INFO "Only root user can change the status");
        return -EPERM;
    }

    /* kmalloc pwd in kernel space */
    kernel_pwd = kmalloc(PWD_LEN, GFP_KERNEL);
	if (!kernel_pwd){
		printk("%s: Error kernel password allocation", MODNAME);
        	return -ENOMEM; 
		}
			
	// Copy pwd from user space
	if (copy_from_user(kernel_pwd, password, PWD_LEN)) {
		printk("%s: Error during password copy from user",MODNAME);
		kfree(kernel_pwd);
		return -EFAULT;
	}

    /* check if insert pwd is valid*/
    if (strcmp(reference_monitor.password, get_pwd_encrypted(kernel_pwd)) != 0){
        printk("%s: Invalid password, change state not allowed", MODNAME);
        kfree(kernel_pwd);
        return -EACCES;
    }

    kfree(kernel_pwd);

    /* remove path from list is allowed only in REC_ON or REC_OFF */
    if (reference_monitor.state == ON || reference_monitor.state == OFF){
        printk("%s: state is %s, it's not allowed to add a new path in protected_paths list", MODNAME, reference_monitor.state);
        return -EPERM;
    }

    kernel_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kernel_path)
		return -ENOMEM; 

	/* Copy the path from user space, PATH_MAX is 4096, max path size in kernel  */
	if (copy_from_user(kernel_path, path, PATH_MAX)) {
		kfree(kernel_path);
		return -EFAULT;
	}

    if (!file_in_protected_paths_list(kernel_path)){
        printk("%s: Path %s is in protected_paths list\n", MODNAME, kernel_path);
        return -EINVAL;
    }

    inode_number = get_inode_from_path(kernel_path); //funzione 
    if (inode_number == 0)
        //not valid path
        return 0;

    spin_lock(&reference_monitor.rf_lock); //TODO: in questo modo viene tolto un solo nodo, se vuoi togli if e elimina tutti i nodi
    list_for_each_entry_safe(entry_list, tmp, &reference_monitor.protected_paths, list){
        if (entry_list->inode_n == inode_number) {
            list_del(&entry_list->list);
            kfree(entry_list);
            spin_unlock(&reference_monitor.rf_lock);
            return 0;     
        }
    }
    spin_unlock(&reference_monitor.rf_lock);

    return -EINVAL; //ok
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _print_protected_paths, char*, output_buff, char*, password){
#else
asmlinkage int sys_print_protected_paths;(char __user * pw, int pw_size){
#endif

    char* kernel_pwd;
    char* kernel_output;
    struct protected_paths_entry *entry_list, *tmp;
    int written_chars = 0;
    size_t busy_space = 0, rem_space_output;
    int ret = 0;


    /* check if user is root EUID 0 */
    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)){ 
        printk(KERN_INFO "Only root user can change the status");
        return -EPERM;
    }

    /* kmalloc pwd in kernel space */
    kernel_pwd = kmalloc(PWD_LEN, GFP_KERNEL);
	if (!kernel_pwd){
		printk("%s: Error kernel password allocation", MODNAME);
        	return -ENOMEM; 
		}
			
	// Copy pwd from user space
	if (copy_from_user(kernel_pwd, password, PWD_LEN)) {
		printk("%s: Error during password copy from user",MODNAME);
		kfree(kernel_pwd);
		return -EFAULT;
	}

    /* check if insert pwd is valid*/
    if (strcmp(reference_monitor.password, get_pwd_encrypted(kernel_pwd)) != 0){
        printk("%s: Invalid password, change state not allowed", MODNAME);
        kfree(kernel_pwd);
        return -EACCES;
    }

    kfree(kernel_pwd);

    kernel_output = kmalloc(OUTPUT_BUFFER_SIZE, GFP_KERNEL);
    if (!kernel_output){
		printk("%s: Error during kernel_output allocation", MODNAME);
        	return -ENOMEM; 
	}

    spin_lock(&reference_monitor.rf_lock); //uso spinlock per avere protezione su lettura e scrittura
    
    list_for_each_entry_safe(entry_list, tmp, &reference_monitor.protected_paths, list){

        rem_space_output = OUTPUT_BUFFER_SIZE - busy_space;

        if(written_chars = snprintf(kernel_output + strlen(kernel_output), rem_space_output, "Path %s, inode_number -> %u\n", entry_list->path, entry_list->inode_n) < 0){
            printk("%s: Failed to copy path in kernel_output", MODNAME);
            ret = -EFAULT;
            spin_unlock(&reference_monitor.rf_lock);
            kfree(kernel_output);
            return ret;
        }
        busy_space += written_chars;
    }

    //copy from kernel to user space output for printing
    if(copy_to_user(output_buff, kernel_output, strlen(kernel_output))!=0){
        printk("%s: Copy_to_user failed \n", MODNAME);
    }

    spin_unlock(&reference_monitor.rf_lock);
    kfree(kernel_output);
    return ret; //0 if ok

}





#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_switch_state = (unsigned long)__x64_sys_switch_state;    
long sys_add_protected_paths = (unsigned long) __x64_sys_add_protected_paths;
long sys_rm_protected_paths = (unsigned long) __x64_sys_rm_protected_paths;
long sys_print_protected_paths = (unsigned long) __x64_sys_print_protected_paths;
#else
#endif

static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void)
{
    write_cr0_forced(cr0);
}

static inline void unprotect_memory(void)
{
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}

int inizialize_syscall(void){

    unsigned long ** sys_call_table_hacked;

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
    
     /* INSTALL NEW SYSCALL */
    cr0 = read_cr0();
    unprotect_memory();
    sys_call_table_hacked = (void*) syscall_table_addr;
    hack_ni_syscall = sys_call_table_hacked[free_entries[0]]; // for cleanup
    //printk("%u", sys_call_table_hacked[134]);
    sys_call_table_hacked[free_entries[0]] = (unsigned long*)sys_switch_state; //134
    //printk("%u", sys_call_table_hacked[134]);
    sys_call_table_hacked[free_entries[1]] = (unsigned long*)sys_add_protected_paths; //156
    sys_call_table_hacked[free_entries[2]] = (unsigned long*)sys_rm_protected_paths; //174
    sys_call_table_hacked[free_entries[3]] = (unsigned long*)sys_print_protected_paths;
    protect_memory();

    printk(KERN_INFO "System call 134 = 0x%lx\n ", sys_call_table_hacked[134]);
    printk("Installed syscall at index %d\n", free_entries[1]);

    int i;
    for(i=0; i<15; i++){
        printk(KERN_INFO "Free entries syscall array[%d] = %d\n", i, free_entries[i]);
    }


    return 0;
}

int ref_monitor_initialize(void){
    
    reference_monitor.state = OFF; //State 0 == OFF
    printk("Initial STATE: %d", reference_monitor.state);

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

    unsigned long **sys_call_table_hacked;
    cr0 = read_cr0();
    unprotect_memory();
    sys_call_table_hacked = (void*) syscall_table_addr;
    sys_call_table_hacked[free_entries[0]] = hack_ni_syscall;
    sys_call_table_hacked[free_entries[1]] = hack_ni_syscall;
    sys_call_table_hacked[free_entries[2]] = hack_ni_syscall;
    sys_call_table_hacked[free_entries[3]] = hack_ni_syscall;
    protect_memory();

    printk("%s: state at  shutdown is: %d", MODNAME, reference_monitor.state);

    printk("%s: shutting down\n",MODNAME);

    return;
}