#define PWD_LEN 32


struct reference_monitor{
    char *password;                    /* Pwd for reconfiguration*/
    int state;                         /* State of ref_monitor: OFF(0) - ON(1) - REC-OFF(2) - REC-ON(3) */
    struct list_head protected_paths;
    //aggiungi list blackist file e dir
}