#define PWD_LEN 32

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "linux/spinlock.h"


struct reference_monitor{
    char *password;                    /* Pwd for reconfiguration*/
    int state;                         /* State of ref_monitor: OFF(0) - ON(1) - REC-OFF(2) - REC-ON(3) */
    struct list_head protected_paths;
    spinlock_t rf_lock;
    //aggiungi list blackist file e dir
};

//char *get_pwd_encrypted(char *pwd);