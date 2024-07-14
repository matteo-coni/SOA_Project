#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#define PWD_LEN 32
#define OUTPUT_BUFFER_SIZE (PATH_MAX * 512)
#define MAX_PATH_LEN 256

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
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/kprobes.h>

#include "utils.h"

enum State {
    OFF,
    ON,
    REC_OFF,
    REC_ON
};

struct protected_paths_entry{
    struct list_head list;
    char *path;
    unsigned long inode_n; //number of inode
};

struct reference_monitor{
    char *password;                    /* Pwd for reconfiguration*/
    enum State state;                         /* State of ref_monitor: OFF(0) - ON(1) - REC-OFF(2) - REC-ON(3) */
    struct list_head protected_paths;
    spinlock_t rf_lock;
    //aggiungi list blackist file e dir
};

struct info_log{
    pid_t tid;
    pid_t tgid;
    uid_t uid;
    uid_t euid;
    char* pathname;
    char* hash_file_content;
};

struct packed_work{
    struct work_struct work;
    struct info_log *info_log;
};

#endif // REFERENCE_MONITOR_H