#include "utils.h"
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Coni");
MODULE_DESCRIPTION("Kernel Level Reference Monitor Module");



int do_sha256(const char *pwd_input, size_t len_pwd, char *output_hash){
    
    int i;
    int ret = 0;
    struct crypto_shash *alg;
    struct shash_desc *desc;
    char *hash;
    

    // Allocate memory for the hash buffer
    hash = kmalloc(HASH_MAX_DIGESTSIZE , GFP_ATOMIC);
    if (!hash) {
        printk(KERN_ERR "Failed to allocate hash buffer\n");
        return -ENOMEM;
    }
    
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
        return -ENOMEM; //memory error
        
    }

    desc->tfm = alg;

	ret = crypto_shash_digest(desc, pwd_input, len_pwd, output_hash);
    if(ret < 0){
        printk(KERN_ERR "Error during digest computation\n");
        return -EFAULT;
    }

    // Copy the hash to the output buffer in hexadecimal format
    for (i = 0; i < crypto_shash_digestsize(alg); i++) {
        snprintf(output_hash + (i * 2), 3, "%02x", (unsigned int)hash[i] & 0xFF);
    }

    if(desc)
        kfree(desc);
    if(alg)
        crypto_free_shash(alg);
    if(hash)
        kfree(hash);

    return ret;
}


char* get_pwd_encrypted(const char *pwd) {
    // dummy
    printk(KERN_INFO "prova encryption");

    char *pwd_hash;
    do_sha256(pwd, strlen(pwd), pwd_hash);
    return pwd_hash; // 
}

EXPORT_SYMBOL(get_pwd_encrypted); 