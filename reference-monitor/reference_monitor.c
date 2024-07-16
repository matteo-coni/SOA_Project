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
#include "utils.h"

#include <linux/module.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Coni");
MODULE_DESCRIPTION("Kernel Level Reference Monitor Module");

struct reference_monitor reference_monitor;
unsigned long cr0;
spinlock_t defwork_lock;

unsigned long *hack_ni_syscall; 

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

static struct kretprobe vfs_open_retprobe;
static struct kretprobe delete_retprobe;
static struct kretprobe security_mkdir_retprobe;
static struct kretprobe security_inode_create_retprobe;
static struct kretprobe security_inode_link_retprobe;
static struct kretprobe security_inode_symlink_retprobe;
static struct kretprobe security_inode_unlink_retprobe;

const char* filename_handler;

ino_t get_inode_from_path(const char *path){

    struct path file_path;
    int ret;
    ino_t inode;

    //printk("%s: path", path);

    ret = kern_path(path, LOOKUP_FOLLOW, &file_path);
    if (ret){
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
    inode_number = get_inode_from_path(filename_path); 
    if (inode_number == 0){
        //not valid path
        return 0;
    }

    rcu_read_lock();
    list_for_each_entry_safe(entry, tmp, &reference_monitor.protected_paths, list){
        if (entry->inode_n == inode_number) {
            ret = 1;
            goto exit;       
        }
    }
    exit:
    rcu_read_unlock();

    return ret; //ret 1 if present, 0 altrimenti
}

/* system call SWITCH_STATE reference monitor */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2,_switch_state, char*, state, char*, password){
#else
asmlinkage int sys_switch_state(char* state, char __user* password){
#endif

    char* kernel_pwd;
    char* kernel_state;

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

    /* check if insert pwd is valid */
    if (strcmp(reference_monitor.password, get_pwd_encrypted(kernel_pwd)) != 0){
        printk("%s: Invalid password, change state not allowed", MODNAME);
        kfree(kernel_pwd);
        return -EACCES;
    }
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
    
    kfree(kernel_state);

    return 0; //ok
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _add_protected_paths, char *, path, char* , password) {
#else 
asmlinkage long sys_add_protected_paths(char *path, char* password) {
#endif

    char* kernel_pwd;
    char* kernel_path;
    struct protected_paths_entry *entry_list;

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

    /* add new path in list is allowed only in REC_ON or REC_OFF */
    if (reference_monitor.state == ON || reference_monitor.state == OFF){
        printk("%s: state is %s, it's not allowed to add a new path in protected_paths list", MODNAME, (char*)reference_monitor.state);
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
    
    /* ADD FILE IN LIST */
    entry_list = kmalloc(sizeof(struct protected_paths_entry), GFP_KERNEL);
    entry_list->path = kstrdup(kernel_path, GFP_KERNEL);
    entry_list->inode_n = get_inode_from_path(kernel_path); 
    
    spin_lock(&reference_monitor.rf_lock);

    // Insert the new entry into the list under RCU protection
    rcu_read_lock();
    list_add_rcu(&entry_list->list, &reference_monitor.protected_paths);
    rcu_read_unlock();

    spin_unlock(&reference_monitor.rf_lock);

    printk("%s: path %s successfully added to protected_paths list", MODNAME, kernel_path);

    return 0; //ok
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _rm_protected_paths, char *, path, char* , password) {
#else 
asmlinkage long sys_rm_protected_paths(char *path, char __user *  password) {
#endif

    char* kernel_pwd;
    char* kernel_path;
    struct protected_paths_entry *entry_list, *tmp; //entry_list is an entry of list
    ino_t inode_number;

    printk(KERN_INFO "Remove path");

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
        printk("%s: state is %s, it's not allowed to remove path from protected_paths list", MODNAME, (char*)reference_monitor.state);
        return -EPERM;
    }

    kernel_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kernel_path)
		return -ENOMEM; 

	/* Copy the path from user space, PATH_MAX is 4096, max path size in kernel */
	if (copy_from_user(kernel_path, path, PATH_MAX)) {
		kfree(kernel_path);
		return -EFAULT;
	}

    if (!file_in_protected_paths_list(kernel_path)){
        printk("%s: Path %s is not in protected_paths list\n", MODNAME, kernel_path);
        return -EINVAL;
    }

    inode_number = get_inode_from_path(kernel_path);
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
asmlinkage int sys_print_protected_paths;(char* output_buff, char __user * password){
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

        if((written_chars = snprintf(kernel_output + strlen(kernel_output), rem_space_output, "Path %s, inode_number -> %lu\n", entry_list->path, entry_list->inode_n) < 0)){
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
    int i;

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
    sys_call_table_hacked[free_entries[0]] = (unsigned long*)sys_switch_state; //134
    sys_call_table_hacked[free_entries[1]] = (unsigned long*)sys_add_protected_paths; //156
    sys_call_table_hacked[free_entries[2]] = (unsigned long*)sys_rm_protected_paths; //174
    sys_call_table_hacked[free_entries[3]] = (unsigned long*)sys_print_protected_paths;
    protect_memory();

    
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

static int vfs_open_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

        const struct path *path;
        struct file* file;
        struct dentry *dentry;
        fmode_t mode;
        char *full_path;
        struct my_data *data;

        /* retrieve parameters */
        path = (const struct path *)regs->di;
        file = (struct file *)regs->si;

        data = (struct my_data *)ri->data; //pr
        data->filename_handler = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!data->filename_handler) {
            printk(KERN_ERR "entry_handler: kmalloc failed\n");
            return -ENOMEM;
        }

        dentry = path->dentry;
        mode = file->f_mode;

        if (((mode & FMODE_WRITE) || (mode & FMODE_PWRITE)) && ((reference_monitor.state == ON || reference_monitor.state == REC_ON)) ) {

                full_path = get_path_from_dentry(dentry);
                
                if (file_in_protected_paths_list(full_path)) {
                
                        printk("Path %s trovato nella lista, operazione non permessa", full_path); 
                        data->filename_handler = kstrdup(full_path, GFP_ATOMIC);

                        kfree(full_path);

                        /* schedule return handler execution, that will update the return value (fd) to -1  */
                        return 0;
                }
                 kfree(full_path);        
        }

        return 1;
   
}

static int may_delete_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    
    struct dentry *dentry;
    char *full_path;
    struct my_data *data;

    if(reference_monitor.state == OFF || reference_monitor.state == REC_OFF){
        return 1;
    }

    data = (struct my_data *)ri->data; //pr
    data->filename_handler = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!data->filename_handler) {
        printk(KERN_ERR "entry_handler: kmalloc failed\n");
        return -ENOMEM;
    }


    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0) //altrimenti vm out
    dentry = (struct dentry *)regs->dx;
    #else
    dentry = (struct dentry *)regs->si;
    #endif

    full_path = get_path_from_dentry(dentry);

    if (file_in_protected_paths_list(full_path)) {
            
        printk("Path %s trovato nella lista, operazione eliminazione non permessa", full_path);
        data->filename_handler = kstrdup(full_path, GFP_ATOMIC);
                       
        kfree(full_path);

        // schedule return handler execution, 0 == post handler  
        return 0;
    }

    kfree(full_path);

    return 1; //no post handler
}

static int is_within_protected_dirs(const char *full_path) {
    

    struct protected_paths_entry *entry;
    char *path;
    char *slash;
    int found = 0;

    path = kstrdup(full_path, GFP_KERNEL);
    if (!path) {
        printk(KERN_ERR "kstrdup failed in is_within_protected_dirs\n");
        return 0;
    }

    spin_lock(&reference_monitor.rf_lock);

    while ((slash = strrchr(path, '/')) != NULL) {
        *slash = '\0'; // Termina la stringa al carattere slash

        list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
            if (strcmp(path, entry->path) == 0) {
                found = 1;
                break;
            }
        }

        if (found)
            break;
    }

    spin_unlock(&reference_monitor.rf_lock);

    kfree(path);
    return found;
}

static int security_mkdir_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct dentry *dentry;
    char *full_path;
    struct my_data *data;

    if(reference_monitor.state == OFF || reference_monitor.state == REC_OFF){
        return 1;
    }

    printk("sono in handler mkdir");
    data = (struct my_data *)ri->data; //per pathname
    data->filename_handler = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!data->filename_handler) {
        printk(KERN_ERR "entry_handler: kmalloc failed\n");
        return -ENOMEM;
    }


    dentry = (struct dentry *)regs->si; //si perché su x86_64 è il secondo argomento e corrisponde a dentry nella mkdir

    full_path = get_path_from_dentry(dentry);
    if (!full_path) {
        printk(KERN_ERR "Failed to get full path\n");
        return 1;
    }

    if (is_within_protected_dirs(full_path)) {
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, creazione non permessa\n", full_path);
        data->filename_handler = kstrdup(full_path, GFP_ATOMIC);
        kfree(full_path);
        //regs->ax = -EACCES;
        return 0; //post handler
    }

    kfree(full_path);

    return 1; //no post handler
}

//handler per inode_create all'interno di directory protette
static int security_create_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    
    struct dentry *dentry;
    char *full_path;
    struct my_data *data;

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

    data = (struct my_data *)ri->data; //pr
    data->filename_handler = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!data->filename_handler) {
        printk(KERN_ERR "entry_handler: kmalloc failed\n");
        return -ENOMEM;
    }

    dentry = (struct dentry *)regs->si;  // Su x86_64, rsi corrisponde al secondo argomento

    full_path = get_path_from_dentry(dentry);

    if (!full_path) {
        printk(KERN_ERR "Failed to get full path\n");
        return 1;
    }

    //printk(KERN_INFO "security_create_handler: full path is %s\n", full_path);

    if (is_within_protected_dirs(full_path)) {
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, creazione non permessa\n", full_path);
        data->filename_handler = kstrdup(full_path, GFP_ATOMIC);
        kfree(full_path);
        return 0;
    }

    kfree(full_path);
    return 1; // no post handler
}

//handler per la creazione di un hard link su un path protetto o su un path in una directory protetta
static int security_link_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct dentry *old_dentry, *new_dentry;
    char *old_path, *new_path;
    struct my_data *data;

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

    printk(KERN_INFO "Handler link\n");

    old_dentry = (struct dentry *)regs->di;  // Su x86_64, rdi corrisponde al primo argomento (old_dentry)
    new_dentry = (struct dentry *)regs->dx;  // Su x86_64, rdx corrisponde al terzo argomento (new_dentry)

    old_path = get_path_from_dentry(old_dentry);
    new_path = get_path_from_dentry(new_dentry);

    if (!old_path || !new_path) {
        printk(KERN_ERR "Failed to get full path in security_link_handler\n");
        kfree(old_path);
        kfree(new_path);
        return 1;
    }

    data = (struct my_data *)ri->data; //pr
    data->filename_handler = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!data->filename_handler) {
        printk(KERN_ERR "entry_handler: kmalloc failed\n");
        return -ENOMEM;
    }


    if (is_within_protected_dirs(old_path) || is_within_protected_dirs(new_path) ) {
        printk(KERN_INFO "Path %s o %s è all'interno di una directory protetta, creazione link non permessa\n", old_path, new_path);
        data->filename_handler = kstrdup(old_path, GFP_ATOMIC);
        kfree(old_path);
        kfree(new_path);
        return 0;
    }

    if (file_in_protected_paths_list(old_path)) {
            
        printk(KERN_INFO "Path %s trovato nella lista, creazione link non permessa\n", old_path); //prova test ok funziona
        kfree(old_path);
        data->filename_handler = kstrdup(old_path, GFP_ATOMIC);
        kfree(new_path); 
        printk("prova %s e oldpath: %s", data->filename_handler, old_path);
    
        return 0;
    }

    kfree(old_path);
    kfree(new_path);
    return 1; //no handler post
}

static int security_symlink_handler(struct kretprobe_instance *p, struct pt_regs *regs){
    
    struct dentry *old_dentry;
    char *old_path;
    struct my_data *data;

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

    printk(KERN_INFO "sono in handler symlink\n");

    old_dentry = (struct dentry *)regs->dx;  // Su x86_64, rdx corrisponde al terzo argomento (old_dentry)

    old_path = get_path_from_dentry(old_dentry);

    data = (struct my_data *)p->data; //pr
    data->filename_handler = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!data->filename_handler) {
        printk(KERN_ERR "entry_handler: kmalloc failed\n");
        return -ENOMEM;
    }

    if (!old_path) {
        printk(KERN_ERR "Failed to get full path in security_symlink_handler\n");
        return 1;
    }

    if (is_within_protected_dirs(old_path)) {
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, creazione symlink non permessa\n", old_path);
        data->filename_handler = kstrdup(old_path, GFP_ATOMIC);
        kfree(old_path);
        return 0;
    }

    kfree(old_path);
    return 1; 
}

static int security_unlink_handler(struct kretprobe_instance *p, struct pt_regs *regs){
    
    struct dentry *dentry;
    char *path;
    struct my_data *data;

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

    data = (struct my_data *)p->data; 
    data->filename_handler = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!data->filename_handler) {
        printk(KERN_ERR "entry_handler: kmalloc failed\n");
        return -ENOMEM;
    }

    dentry = (struct dentry *)regs->si;  // Su x86_64, rsi corrisponde al secondo argomento in unlink (dentry)

    path = get_path_from_dentry(dentry);

    if (!path) {
        printk(KERN_ERR "Failed to get full path in security_unlink_handler\n");
        return 1;
    }

    if (is_within_protected_dirs(path)) {
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, eliminazione non permessa\n", path);
        data->filename_handler = kstrdup(path, GFP_ATOMIC);
        kfree(path);
        regs->ax = -EACCES; // Imposta il valore di ritorno a "Permesso negato"
        return 0;
    }

    if (file_in_protected_paths_list(path)) {
        printk(KERN_INFO "Path %s trovato nella lista, eliminazione non permessa\n", path);
        data->filename_handler = kstrdup(path, GFP_ATOMIC);
        kfree(path);
        regs->ax = -EACCES; // Imposta il valore di ritorno a "Permesso negato"
        return 0;
    }

    kfree(path);
    return 1;
}

static int calculate_fingerprint(char* pathname, char* hash_out){
    
    struct file *file;
    char *file_content;
    int file_size;
    int ret = -1;
    int i;
    
    file = filp_open(pathname, O_RDONLY, 0644);
    if (!file || IS_ERR(file)) {
        printk("Failed to open file %s with error %ld\n", pathname, PTR_ERR(file));
        ret = -ENOENT;
    }

    file_size = i_size_read(file_inode(file));
    if (file_size <= 0) {
        printk("Invalid file size\n");
        filp_close(file, NULL);
        ret = -EINVAL;
         
    }

    file_content = kmalloc(file_size, GFP_KERNEL);
    if (!file_content) {
        printk( "Failed to allocate memory for file content\n");
        filp_close(file, NULL);
        ret = -ENOMEM;
    }


    ret = kernel_read(file, file_content, file_size, &file->f_pos);
    if (ret < 0) {
        printk("Failed to read file content\n");
        kfree(file_content);
        filp_close(file, NULL);
        return ret;
    }

    ret = do_sha256(file_content, file_size, hash_out);
    if (ret < 0) {
        printk(KERN_ERR "Failed to calculate SHA-256 hash\n");
        kfree(file_content);
        filp_close(file, NULL);
        return ret;
    }

    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        snprintf(hash_out + (i * 2), 3, "%02x", (unsigned int)hash_out[i] & 0xFF);
    }
    hash_out[SHA256_DIGEST_SIZE * 2] = '\0'; // Null terminator
    
    kfree(file_content);
    filp_close(file, NULL);

    return 0; //0 = success
}

void handler_def_work(struct work_struct *work_data){
    
    int ret;
    struct file *file_log_output;
    char log_data[256];

    struct packed_work *pck_work = container_of(work_data, struct packed_work, work);
    if(!pck_work){
        printk("Error during packed_work container_of");
    }

    printk("handler_def_work: fingerprint for path %s", pck_work->info_log->pathname_file);

    ret = calculate_fingerprint(pck_work->info_log->pathname_file, pck_work->info_log->hash_file_content); //0 == ok
    if (ret != 0) {
        printk(KERN_ERR "Impossibile calcolare l'hash per %s\n", pck_work->info_log->pathname);
        kfree(pck_work);
        return;
    }


    file_log_output = filp_open(PATH_LOG_FILE, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(file_log_output)) {
        int err = PTR_ERR(file_log_output);
        printk("Error on opening log file: %d \n", err);
        ret = err;
        //pulisci mem
    }

    //formattazione pre scrittura file
    snprintf(log_data, 256, "TGID: %d, TID: %d, UID: %u, EUID: %u, Exe_PATH: %s, HASH: %s\n", pck_work->info_log->tgid, pck_work->info_log->tid, pck_work->info_log->uid, pck_work->info_log->euid, pck_work->info_log->pathname, pck_work->info_log->hash_file_content);

    ret = kernel_write(file_log_output, log_data, strlen(log_data), &file_log_output->f_pos);

    filp_close(file_log_output, NULL);

    return;
    

}

/* function for collect info like as TID, TGID, UID, EUID and schedule deferred work */
static void collect_info(const char *pathname){

    struct info_log *info_log;
    struct packed_work *packed_work;
    struct mm_struct *mm;
    struct file *exe_file;
    char *path_buffer;
    struct dentry *exe_dentry;
    char *path_file;

    //spin_lock(&defwork_lock);
    if (!pathname) {
        printk(KERN_ERR "collect_info: pathname is NULL\n");
        return;
    }

    info_log = kmalloc(sizeof(struct info_log), GFP_ATOMIC);
        if (!info_log) {
                pr_err("%s: error in kmalloc allocation (info_log)\n", MODNAME);
                //spin_unlock(&defwork_lock);
                return;
        }

    packed_work = kmalloc(sizeof(struct packed_work), GFP_KERNEL);
    if (!packed_work) {
        pr_err("%s: error in kmalloc allocation (packed_work)\n", MODNAME);
        kfree(info_log);
        return;
    }

    info_log->hash_file_content = kmalloc(SHA256_DIGEST_SIZE * 2 + 1, GFP_KERNEL);
    if (!info_log->hash_file_content) {
        pr_err("%s: error in kmalloc allocation (hash_file_content)\n", MODNAME);
        kfree(info_log->pathname);
        kfree(info_log);
        kfree(packed_work);
        return;
    }

    info_log->uid = current_uid().val;
    info_log->euid = current_euid().val;
    info_log->tid = current->pid;
    info_log->tgid = task_tgid_vnr(current);
    
    mm = current->mm;
    if (!mm) {
        kfree(packed_work);
        return;
    }

    exe_file = mm->exe_file;
    if (!exe_file) {
        kfree(packed_work);
        return;
    }

    exe_dentry = mm->exe_file->f_path.dentry;
    path_file = get_path_from_dentry(exe_dentry);
    info_log->pathname = kstrdup(path_file, GFP_ATOMIC); //cosi metto il comando

    info_log->pathname_file = kstrdup(pathname, GFP_ATOMIC);


    path_buffer = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
    if (!path_buffer) {
        kfree(packed_work);
        return;
    }

    packed_work->info_log = info_log;

    kfree(path_buffer);

    wq = alloc_workqueue("REFERENCE_MONITOR_WORKQUEUE", WQ_MEM_RECLAIM, 1); //queue for deferred work

    INIT_WORK(&packed_work->work, handler_def_work); 
    if (!queue_work(wq, &packed_work->work)) {
        pr_err("%s: failed to queue work\n", MODNAME);
        goto cleanup;
    }
    //schedule_work(&packed_work->work);

    printk(KERN_INFO "collect_info: work queued\n");
    return;

cleanup:
    if (info_log) {
        kfree(info_log->pathname);
        kfree(info_log->hash_file_content);
        kfree(info_log);
    }
    kfree(packed_work);
    kfree(path_buffer);
}

static int post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    
    struct my_data *data = (struct my_data *)p->data;
    the_regs->ax = -EACCES;
    
    printk("%s: actions blocked\n", MODNAME);
    
    if (data->filename_handler) {
        printk(KERN_INFO "post_handler: blocking action and collecting info for %s\n", data->filename_handler);
        collect_info(data->filename_handler);
        //kfree(data->filename_handler);
    }

    return 0;
}

static void set_kretprobe(struct kretprobe *krp, char *symbol_name, kretprobe_handler_t entry_handler) {
        krp->kp.symbol_name = symbol_name;
        krp->entry_handler = entry_handler;
        krp->handler = (kretprobe_handler_t)post_handler;
        krp->maxactive = -1;
}

static int init_kretprobe(void){

    int ret;

    set_kretprobe(&vfs_open_retprobe, "vfs_open", (kretprobe_handler_t)vfs_open_handler);
    set_kretprobe(&delete_retprobe, "may_delete", may_delete_handler);
    set_kretprobe(&security_mkdir_retprobe, "security_inode_mkdir", (kretprobe_handler_t)security_mkdir_handler);
    set_kretprobe(&security_inode_create_retprobe, "security_inode_create", (kretprobe_handler_t)security_create_handler);
    set_kretprobe(&security_inode_link_retprobe, "security_inode_link", (kretprobe_handler_t)security_link_handler);
    set_kretprobe(&security_inode_symlink_retprobe, "security_inode_symlink", (kretprobe_handler_t)security_symlink_handler);
    set_kretprobe(&security_inode_unlink_retprobe, "security_inode_unlink", (kretprobe_handler_t)security_unlink_handler);
    
    
    printk("INIT KRETPROBE");

    ret = register_kretprobe(&vfs_open_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe for vfs_open failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kretprobe for vfs_open registered\n");
    
    ret = register_kretprobe(&delete_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe for delete failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kretprobe for may_delete registered\n");
    
    ret = register_kretprobe(&security_mkdir_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe for mkdir failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kretprobe for security_inode_mkdir registered\n");

    ret = register_kretprobe(&security_inode_create_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe for inode_create failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kretprobe for security_inode_create registered\n");

    ret = register_kretprobe(&security_inode_link_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe for inode_link failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kretprobe for security_inode_link registered\n");

    ret = register_kretprobe(&security_inode_symlink_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe for inode_symlink failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kretprobe for security_inode_symlink registered\n");

    ret = register_kretprobe(&security_inode_unlink_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe for inode_unlink failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kretprobe for security_inode_unlink registered\n");

    return 0;
}

int init_module(void) {
    int ret;
    char *pwd_encrypted = NULL;;

    printk(KERN_INFO "Initializing reference monitor\n");
    
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

    pwd_encrypted = get_pwd_encrypted(password); 
    if (!pwd_encrypted) {
        printk(KERN_ERR "Failed to encrypt password\n");
        return -ENOMEM;
    }
    
    
    reference_monitor.password = pwd_encrypted;    
    printk(KERN_INFO "pwd_encrypted ref monitor = %s\n", reference_monitor.password); //pwd ok

    init_kretprobe(); //initialize the kretprobe for write

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

    unregister_kretprobe(&vfs_open_retprobe);
    unregister_kretprobe(&delete_retprobe);
    unregister_kretprobe(&security_mkdir_retprobe);
    unregister_kretprobe(&security_inode_create_retprobe);
    unregister_kretprobe(&security_inode_link_retprobe);
    unregister_kretprobe(&security_inode_symlink_retprobe);
    unregister_kretprobe(&security_inode_unlink_retprobe);
    printk(KERN_INFO "kretprobes unregistered\n");

    printk("%s: shutting down\n",MODNAME);

    return;
}