#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uio.h>

#include "singlefilefs.h"


ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    loff_t offset;
    int block_to_read;//index of the block to be read from device

    printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)",MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason

    //check that *off is within boundaries
    if (*off >= file_size)
        return 0;
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
	return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    return len - ret;

}

static ssize_t append_write_iter(struct kiocb *iocb, struct iov_iter *from) {
    
    loff_t blocco_offset, offset_corrente;
    int blocco_da_scrivere;
    struct buffer_head *buffer_testa = NULL;
    size_t bytes_copiati, dimensione;
    struct file *file_corrente;
    struct inode *inode_corrente;
    uint64_t dimensione_file;
    char *dati;

    file_corrente = iocb->ki_filp;
    inode_corrente = file_corrente->f_inode;
    offset_corrente = file_corrente->f_pos;
    dimensione_file = i_size_read(inode_corrente);

    /* byte size of the payload */
    dimensione = from->count;

    dati = kmalloc(dimensione, GFP_KERNEL);
    if (!dati) {
        pr_err("%s: error in kmalloc allocation\n", MOD_NAME);
        
        return 0;
    }

    bytes_copiati = _copy_from_iter((void *)dati, dimensione, from);
    if (bytes_copiati != dimensione) {
        pr_err("%s: failed to copy %ld bytes from iov_iter\n", MOD_NAME, dimensione);
        
        return 0;
    }

    pr_info("%s: Trying to write string: %s", MOD_NAME, dati);

    offset_corrente = dimensione_file;

    /* APPEND */
    blocco_offset = offset_corrente % DEFAULT_BLOCK_SIZE;
    blocco_da_scrivere = offset_corrente / DEFAULT_BLOCK_SIZE + 2;  // + superblock + inode

    if (4096 - blocco_offset < dimensione) {
        blocco_da_scrivere++;
        offset_corrente += (4096 - blocco_offset);
        blocco_offset = 0;
    }

    buffer_testa = sb_bread(file_corrente->f_path.dentry->d_inode->i_sb, blocco_da_scrivere);
    if (!buffer_testa) {
        
        return -EIO;
    }

    memcpy(buffer_testa->b_data + blocco_offset, dati, dimensione);

    mark_buffer_dirty(buffer_testa);

    if (offset_corrente + dimensione > dimensione_file)
        i_size_write(inode_corrente, offset_corrente + dimensione);

    brelse(buffer_testa);

    offset_corrente += dimensione;

    kfree(dati);
    
    return dimensione;
}




struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

	
	//get a locked inode from the cache 
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
       		 return ERR_PTR(-ENOMEM);

	//already cached inode - simply return successfully
	if(!(the_inode->i_state & I_NEW)){
		return child_dentry;
	}


	//this work is done if the inode was not already cached
	 #if LINUX_VERSION_CODE <= KERNEL_VERSION(5,12,0)
        inode_init_owner(the_inode, NULL, S_IFREG);
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)
        inode_init_owner(&init_user_ns,the_inode, NULL, S_IFREG);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
        inode_init_owner(&nop_mnt_idmap,the_inode, NULL, S_IFREG);
    #endif

	the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
	the_inode->i_op = &onefilefs_inode_ops;

	//just one link for this file
	set_nlink(the_inode,1);

	//now we retrieve the file size via the FS specific inode, putting it into the generic inode
    	bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
    	if(!bh){
		iput(the_inode);
		return ERR_PTR(-EIO);
    	}
	FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
	the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
	dget(child_dentry);

	//unlock the inode to make it usable 
    	unlock_new_inode(the_inode);

	return child_dentry;
    }

    return NULL;

}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = append_write_iter //please implement this function to complete the exercise
};
