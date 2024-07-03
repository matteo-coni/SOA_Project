#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#define PWD_LEN 32

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "linux/spinlock.h"
#include <linux/syscalls.h>
#include <linux/err.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

#include "utils.h"

enum State {
    OFF,
    ON,
    REC_OFF,
    REC_ON
};


struct reference_monitor{
    char *password;                    /* Pwd for reconfiguration*/
    enum State state;                         /* State of ref_monitor: OFF(0) - ON(1) - REC-OFF(2) - REC-ON(3) */
    struct list_head protected_paths;
    spinlock_t rf_lock;
    //aggiungi list blackist file e dir
};


#endif // REFERENCE_MONITOR_H