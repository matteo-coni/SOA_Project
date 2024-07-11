#include "utils.h"
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Coni");
MODULE_DESCRIPTION("Kernel Level Reference Monitor Module");

//prova
char *get_path_from_dentry(struct dentry *dentry) {

	char *buffer, *full_path, *ret;
        int len;

        buffer = (char *)__get_free_page(GFP_ATOMIC);
        if (!buffer)
                return NULL;

        ret = dentry_path_raw(dentry, buffer, PATH_MAX);
        if (IS_ERR(ret)) {
                pr_err("dentry_path_raw failed: %li", PTR_ERR(ret));
                free_page((unsigned long)buffer);
                return NULL;
        } 

        len = strlen(ret);

        full_path = kmalloc(len + 2, GFP_ATOMIC);
        if (!full_path) {
                pr_err("error in kmalloc allocation (get_path_from_dentry)\n");
                return NULL;
        }

        strncpy(full_path, ret, len);
        full_path[len + 1] = '\0';

        free_page((unsigned long)buffer);
        return full_path;
}




int do_sha256(const char *pwd_input, size_t len_pwd, char *output_hash){
    
    int i;
    int ret = 0;
    struct crypto_shash *alg;
    struct shash_desc *desc;
    
    /* Cipher handle for a message digest. 
	The returned struct crypto_shash is the cipher 
	handle required for any subsequent API invocation
	 for that message digest.*/
    alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(alg)) {
        printk(KERN_ERR "Failed to allocate crypto shash error code %ld\n",PTR_ERR(alg));
        return PTR_ERR(alg);
    }

    //memory for hash descriptor
    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(alg), GFP_ATOMIC);
    if (!desc) {
        printk(KERN_ERR "Failed to allocate shash descriptor\n");
        crypto_free_shash(alg);
        return -ENOMEM; //memory error
        
    }

    desc->tfm = alg;

	ret = crypto_shash_digest(desc, pwd_input, len_pwd, output_hash);
    if(ret){
        printk(KERN_ERR "Error during digest computation\n");
        return -EFAULT;
    }

    if(desc)
        kfree(desc);
    if(alg)
        crypto_free_shash(alg);

    return ret;
}


char* get_pwd_encrypted(const char *pwd) {
    // dummy
    printk(KERN_INFO "prova encryption pwd = %s", pwd);

    int i;
    char *pwd_hash;
    int hash_len = SHA256_DIGEST_SIZE;

    // Allocate memory for the hash output
    pwd_hash = kmalloc(hash_len * 2 + 1, GFP_KERNEL); // +1 for null terminator
    if (!pwd_hash) {
        printk(KERN_ERR "Failed to allocate memory for password hash\n");
        return NULL;
    }

    char hash[SHA256_DIGEST_SIZE]; //come buffer per il ritorno
    if (do_sha256(pwd, strlen(pwd), hash)) {
        kfree(pwd_hash);
        return NULL;
    }

    // Convert the hash to a hexadecimal string
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        snprintf(pwd_hash + (i * 2), 3, "%02x", (unsigned int)hash[i] & 0xFF);
    }
    pwd_hash[hash_len * 2] = '\0'; // null terminator

    printk(KERN_INFO "pwd encrypted = %s", pwd_hash);
    printk(KERN_INFO "pwd_hash_global address = %px", (void*)pwd_hash);
    //qui ok ma verifica return pwd

    return pwd_hash;
}

EXPORT_SYMBOL(get_pwd_encrypted);
//EXPORT_SYMBOL(get_path_from_dentry);