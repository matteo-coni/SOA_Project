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
MODULE_PARM_DESC(syscall_table_addr, "Syscall_table address parameter"); 

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

    /* check if insert pwd is valid (same as mount pwd) */
    if (strcmp(reference_monitor.password, get_pwd_encrypted(kernel_pwd)) != 0){
        printk("%s: Invalid password, change state not allowed", MODNAME);
        kfree(kernel_pwd);
        return -EACCES;
    }
    kfree(kernel_pwd);

    kernel_state = kmalloc(20, GFP_KERNEL);
	if (!kernel_state){
		printk("%s: Error kernel_state allocation", MODNAME);
        	return -ENOMEM; 
		}
	
	// Copy state from user space
	if (copy_from_user(kernel_state, state, PWD_LEN)) {
		printk("%s: Error during state copy from user",MODNAME);
		kfree(kernel_state);
		return -EFAULT;
	}
    printk("prova state kernel: %s", kernel_state);
    
    spin_lock(&reference_monitor.rf_lock);
    
    if(strcmp(kernel_state, "ON")==0){
        
        reference_monitor.state = ON;
        printk("%s: Switching rm state to ON", MODNAME);
        
    } else if(strcmp(kernel_state, "OFF") == 0){
        
        reference_monitor.state = OFF;
        printk("%s: Switching rm state to OFF", MODNAME);

    } else if(strcmp(kernel_state, "REC_OFF") == 0){

        reference_monitor.state = REC_OFF;
        printk("%s: Switching rm state to REC_OFF", MODNAME);

    } else if(strcmp(kernel_state, "REC_ON") == 0){
        
        reference_monitor.state = REC_ON;
        printk("%s: Switching rm state to REC_ON", MODNAME);

    } else {
        printk("No IF taken... exit. ") ;
    }
    spin_unlock(&reference_monitor.rf_lock);
    
    kfree(kernel_state);

    return 0; //ok
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _add_protected_paths, char *, path, char* , password) {
#else 
asmlinkage long sys_add_protected_paths(char *path, char __user * password) {
#endif

    char* kernel_pwd;
    char* kernel_path;
    struct protected_paths_entry *entry_list;
    struct path kern_path_str;
    int check;

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

    check = kern_path(kernel_path,LOOKUP_FOLLOW, &kern_path_str); //checking the path validity
    if(check){
        printk("%s: file or directory doesn't exists \n", MODNAME);
        return -ENOMEM;
    }
    
    if (file_in_protected_paths_list(kernel_path)){
        printk("%s: Path %s is already in protected_paths list\n", MODNAME, kernel_path);
        return -EINVAL;
    }
    
    /* ADD FILE TO LIST */
    entry_list = kmalloc(sizeof(struct protected_paths_entry), GFP_KERNEL);
    entry_list->path = kstrdup(kernel_path, GFP_KERNEL);
    entry_list->inode_n = get_inode_from_path(kernel_path); 
	printk("inode del file: %lu", entry_list->inode_n);
    
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
asmlinkage int sys_print_protected_paths(char* output_buff, char __user * password){
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

    kernel_output = kzalloc(OUTPUT_BUFFER_SIZE, GFP_KERNEL);
    if (!kernel_output){
		printk("%s: Error during kernel_output allocation", MODNAME);
        	return -ENOMEM; 
	}

    spin_lock(&reference_monitor.rf_lock); //uso spinlock per avere protezione su lettura e scrittura
    
    list_for_each_entry_safe(entry_list, tmp, &reference_monitor.protected_paths, list){

        rem_space_output = OUTPUT_BUFFER_SIZE - busy_space;

        if((written_chars = snprintf(kernel_output + strlen(kernel_output), rem_space_output, "Path %s, inode_number -> %lu\n", entry_list->path, entry_list->inode_n)) < 0){
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
    sys_call_table_hacked[free_entries[0]] = (unsigned long*)sys_switch_state; 
    sys_call_table_hacked[free_entries[1]] = (unsigned long*)sys_add_protected_paths; 
    sys_call_table_hacked[free_entries[2]] = (unsigned long*)sys_rm_protected_paths; 
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
        char *full_path;
        int flag;

        if(reference_monitor.state == OFF || reference_monitor.state == REC_OFF){
            return 1;
        }

        /* retrieve parameters */
        path = (const struct path *)regs->di;
        file = (struct file *)regs->si;
        flag = file->f_flags;
        dentry = path->dentry;

    
        if (flag & O_WRONLY || flag & O_RDWR || flag & O_CREAT || flag & O_APPEND || flag & O_TRUNC){

                full_path = get_path_from_dentry(dentry);
                if (file_in_protected_paths_list(full_path)) {

                        printk("Path %s trovato nella lista, operazione non permessa", full_path); 
                        kfree(full_path);

                        /* ret 0 for post_handler execution  */
                        return 0;
                }
                 kfree(full_path);        
        }
        return 1;
   
}

static int may_delete_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    
    struct dentry *dentry;
    char *full_path;
    

    if(reference_monitor.state == OFF || reference_monitor.state == REC_OFF){
        return 1;
    }

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0) //altrimenti vm out
    dentry = (struct dentry *)regs->dx;
    #else
    dentry = (struct dentry *)regs->si;
    #endif

    full_path = get_path_from_dentry(dentry);

    if (file_in_protected_paths_list(full_path)) {   
        printk("Path %s trovato nella lista, operazione eliminazione non permessa", full_path);             
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

    //gerarchia directory
    while ((slash = strrchr(path, '/')) != NULL) {
        
        *slash = '\0'; 
        
        list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
            if (strcmp(path, entry->path) == 0) {
                found = 1;
                break;
            }
        }

        if (found) {
            break;
        }

        // Se siamo alla root (path vuoto), usciamo dal while
        if (slash == path) {
            break;
        }
    }

    spin_unlock(&reference_monitor.rf_lock);
    kfree(path);

    return found;
}


static int security_mkdir_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {

    struct dentry *dentry;
    char *full_path;

    if(reference_monitor.state == OFF || reference_monitor.state == REC_OFF){
        return 1;
    }

    dentry = (struct dentry *)regs->si; //si perché su x86_64 è il secondo argomento e corrisponde a dentry nella mkdir

    full_path = get_path_from_dentry(dentry);
    if (!full_path) {
        printk(KERN_ERR "Failed to get full path\n");
        return 1;
    }


    if (is_within_protected_dirs(full_path)) {
        
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, creazione non permessa\n", full_path);
        kfree(full_path);
        
        return 0; //post handler
    }

    kfree(full_path);
    return 1; //no post handler
}

//handler per inode_create all'interno di directory protette
static int security_create_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    
    struct dentry *dentry;
    char *full_path;

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

    dentry = (struct dentry *)regs->si;  // Su x86_64, rsi corrisponde al secondo argomento

    full_path = get_path_from_dentry(dentry);

    if (!full_path) {
        printk(KERN_ERR "Failed to get full path\n");
        return 1;
    }


    if (is_within_protected_dirs(full_path)) {
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, creazione non permessa\n", full_path);
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

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

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

    if (is_within_protected_dirs(old_path) || is_within_protected_dirs(new_path) ) {
        printk(KERN_INFO "Path %s o %s è all'interno di una directory protetta, creazione link non permessa\n", old_path, new_path);
        
        kfree(old_path);
        kfree(new_path);
        return 0;
    }

    if (file_in_protected_paths_list(old_path)) {
         
        printk(KERN_INFO "Path %s trovato nella lista, creazione link non permessa\n", old_path); 
        
        kfree(old_path);
        return 0;
    }

    kfree(old_path);
    kfree(new_path);
    return 1; //no handler post
}

static int security_symlink_handler(struct kretprobe_instance *p, struct pt_regs *regs){
    
    struct dentry *new_dentry;
    char *new_path;

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

    new_dentry = (struct dentry *)regs->si;  // Su x86_64, rsi corrisponde al secondo argomento (dentry in "ln -s")
    new_path = get_path_from_dentry(new_dentry);


    if (!new_path) {
        printk(KERN_ERR "Failed to get full path in security_symlink_handler\n");
        return 1;
    }
    
    if (is_within_protected_dirs(new_path)) {
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, creazione symlink non permessa\n", new_path);
        kfree(new_path);
        return 0;
    }

    if (file_in_protected_paths_list(new_path)) {
            
        printk(KERN_INFO "Path %s trovato nella lista, creazione symlink non permessa\n", new_path);
        kfree(new_path);
        
        return 0;
    }

    kfree(new_path);
    return 1; 
}

static int security_unlink_handler(struct kretprobe_instance *p, struct pt_regs *regs){
    
    struct dentry *dentry;
    char *path;

    if (reference_monitor.state == OFF || reference_monitor.state == REC_OFF) {
        return 1;
    }

    dentry = (struct dentry *)regs->si;  // Su x86_64, rsi corrisponde al secondo argomento in unlink (dentry)

    path = get_path_from_dentry(dentry);

    if (!path) {
        printk(KERN_ERR "Failed to get full path in security_unlink_handler\n");
        return 1;
    }

    if (is_within_protected_dirs(path)) {
        printk(KERN_INFO "Path %s è all'interno di una directory protetta, eliminazione non permessa\n", path);
        kfree(path);
        return 0;
    }

    if (file_in_protected_paths_list(path)) {
        printk(KERN_INFO "Path %s trovato nella lista, eliminazione non permessa\n", path);
        kfree(path);
        return 0;
    }

    kfree(path);
    return 1;
}

static int calculate_fingerprint(char* pathname, char* hash_out){
    
    struct file *file;
    char *file_content;
    loff_t pos = 0;
    int file_size;
    int ret;
    unsigned char hash_bin[SHA256_DIGEST_SIZE];
    char hash_hex[SHA256_DIGEST_SIZE * 2 + 1]; // Buffer per rappresentazione esadecimale
    int i;

    file = filp_open(pathname, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open file %s\n", pathname);
        return PTR_ERR(file);
    }

    file_size = i_size_read(file_inode(file));
    if (file_size < 0) {
        printk(KERN_ERR "Invalid file size\n");
        filp_close(file, NULL);
        return -EINVAL;
    }

    file_content = kmalloc(file_size, GFP_KERNEL);
    if (!file_content) {
        printk(KERN_ERR "Failed to allocate memory for file content\n");
        filp_close(file, NULL);
        return -ENOMEM;
    }

    
    ret = kernel_read(file, file_content, file_size, &pos); //read content of file

    if (ret < 0) {
        printk(KERN_ERR "Failed to read file content\n");
        kfree(file_content);
        filp_close(file, NULL);
        return ret;
    }

    ret = do_sha256(file_content, file_size, hash_bin);
    kfree(file_content);
    filp_close(file, NULL);

    if (ret < 0) {
        printk(KERN_ERR "Failed to calculate SHA-256 hash\n");
        return ret;
    }

    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        snprintf(hash_hex + (i * 2), 3, "%02x", hash_bin[i]);
    }
    hash_hex[SHA256_DIGEST_SIZE * 2] = '\0'; //Null terminator

    strncpy(hash_out, hash_hex, SHA256_DIGEST_SIZE * 2 + 1);

    return 0; //0 == sucess
}

void handler_def_work(struct work_struct *work_data){
    
    int ret;
    char log_data[256];

    struct packed_work *pck_work = container_of(work_data, struct packed_work, work);
    if(!pck_work){
        printk("Error during packed_work container_of");
    }

    //pathname is the exe program file
    ret = calculate_fingerprint(pck_work->info_log->pathname, pck_work->info_log->hash_file_content); //0 == ok
    if (ret != 0) {
        printk(KERN_ERR "Impossibile calcolare l'hash per %s\n", pck_work->info_log->pathname);
        kfree(pck_work);
        return;
    }

    //formattazione pre scrittura file
    snprintf(log_data, 256, "TGID: %d, TID: %d, UID: %u, EUID: %u, Exe_PATH: %s, HASH: %s\n", pck_work->info_log->tgid, pck_work->info_log->tid, pck_work->info_log->uid, pck_work->info_log->euid, pck_work->info_log->pathname, pck_work->info_log->hash_file_content);

    ret = kernel_write(reference_monitor.file_log, log_data, strlen(log_data), &reference_monitor.file_log->f_pos);

    return;
}

/* function for collect info like as TID, TGID, UID, EUID and schedule deferred work */
static void collect_info(void){ 

    struct info_log *info_log;
    struct packed_work *packed_work;
    struct mm_struct *mm;
    struct file *exe_file;
    struct dentry *exe_dentry;
    char *path_file;


    info_log = kmalloc(sizeof(struct info_log), GFP_ATOMIC);
        if (!info_log) {
                pr_err("%s: error in kmalloc allocation\n", MODNAME);
                return;
        }

    packed_work = kmalloc(sizeof(struct packed_work), GFP_KERNEL);
    if (!packed_work) {
        pr_err("%s: error in kmalloc allocation\n", MODNAME);
        kfree(info_log);
        return;
    }

    info_log->hash_file_content = kmalloc(SHA256_DIGEST_SIZE * 2 + 1, GFP_KERNEL);
    if (!info_log->hash_file_content) {
        pr_err("%s: error in kmalloc allocation\n", MODNAME);
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

    info_log->pathname = kstrdup(path_file, GFP_ATOMIC); //metto il comando

    packed_work->info_log = info_log;

    wq = alloc_workqueue("REFERENCE_MONITOR_WORKQUEUE", WQ_MEM_RECLAIM, 1); //queue for deferred work

    INIT_WORK(&packed_work->work, handler_def_work);  //deferred work
    if (!queue_work(wq, &packed_work->work)) {
        pr_err("%s: failed to queue work\n", MODNAME);
        goto cleanup;
    }
    
    printk(KERN_INFO "Collect_info: work queued\n");
    return;

cleanup:
    if (info_log) {
        kfree(info_log->pathname);
        kfree(info_log->hash_file_content);
        kfree(info_log);
    }
    kfree(packed_work);
}

static int post_handler(struct kretprobe_instance *p, struct pt_regs *the_regs){
    
    the_regs->ax = -EACCES;
    
    printk("%s: actions blocked\n", MODNAME);
    printk(KERN_INFO "post_handler: blocking action and collecting info \n");
        
    collect_info(); //call function
        
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
    set_kretprobe(&delete_retprobe, "may_delete", (kretprobe_handler_t)may_delete_handler);
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
    //printk(KERN_INFO "pwd_encrypted ref monitor = %s\n", reference_monitor.password); //pwd ok

    init_kretprobe(); //initialize the kretprobe for write

    printk("PATH LOG FILE: %s", PATH_LOG_FILE);
    reference_monitor.file_log = filp_open(PATH_LOG_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(reference_monitor.file_log)) {
        int err = PTR_ERR(reference_monitor.file_log);
        printk("Error on opening log file: %d \n", err);
        ret = err;
    }

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

    if(likely(reference_monitor.file_log)) {
        filp_close(reference_monitor.file_log, NULL);
    }

    printk("%s: shutting down\n",MODNAME);

    return;
}
