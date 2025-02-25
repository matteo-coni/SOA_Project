#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>

#include <linux/version.h>

#define OUTPUT_BUFFER_SIZE (4096 * 512) //4096 is PATH_MAX

void do_switch_state(void){
    char buffer_state[100];
    char buffer_pwd[100];
    long ret; //for ret from syscall
    int c;
    while(1){
    
        printf("Enter new state [OFF] - [REC_OFF] - [ON] - [REC_ON]\n");
        if (fgets(buffer_state, sizeof(buffer_state),stdin)!=NULL){
            size_t len = strlen(buffer_state);
            if (len > 0 && buffer_state[len-1] == '\n') {
                buffer_state[len-1] = '\0';
            }
        } else {
            printf("Error input command, exit...");
            return;
        }
        //check if state input is correct
        if (strcmp(buffer_state, "OFF") == 0 || strcmp(buffer_state, "REC_OFF") == 0 || strcmp(buffer_state, "ON") == 0 || strcmp(buffer_state, "REC_ON") == 0){
            break; //valid
        } else {
            printf("State is invalid, please insert new state... \n");
        }

        while ((c = getchar()) != '\n' && c != EOF) {
            //flush char
        }
    } 
    printf("Enter password: ");
    if (fgets(buffer_pwd, sizeof(buffer_pwd),stdin)!=NULL){
        size_t len = strlen(buffer_pwd);
        if (len > 0 && buffer_pwd[len-1] == '\n') {
            buffer_pwd[len-1] = '\0';
        }
    } else {
        printf("Error input pwd, exit...");
        return;
    }
    //now it's time to call syscall with param state and pwd
    ret = syscall(134,&buffer_state,&buffer_pwd);
    if (ret == 0){
        printf("-- Change state of reference monitor to %s executed successfully ! -- \n", buffer_state);
    } else {
        printf("-- Failed to execute change state! -- \n");
        perror("\nErrore nella syscall_switch_state"); 
    }

    return;
}
void do_add_path(void){
    char buffer_pwd[100];
    char buffer_path[512];
    int ret, c;
    while(1){
    
        printf("Enter new PATH to add of protected paths list\n");
        if (fgets(buffer_path, sizeof(buffer_path),stdin)!=NULL){
            size_t len = strlen(buffer_path);
            if (len > 0 && buffer_path[len-1] == '\n') {
                buffer_path[len-1] = '\0';
            }
        } else {
            printf("Error input command, exit...");
            return;
        }
        // Check if the path is absolute
        if (buffer_path[0] != '/') 
            printf("Error: Path must be absolute\n");
        else{
            if (strlen(buffer_path)==1)
                printf("Error: path is '/' \n");
            else
                break;
        }
    } while ((c = getchar()) != '\n' && c != EOF) {
            //flush characters
        }
    printf("Enter password: ");
    if (fgets(buffer_pwd, sizeof(buffer_pwd),stdin)!=NULL){
        size_t len = strlen(buffer_pwd);
        if (len > 0 && buffer_pwd[len-1] == '\n') {
            buffer_pwd[len-1] = '\0';
        }
    } else {
        printf("Error input pwd, exit...");
        return;
    }

    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    if((ret = syscall(156,&buffer_path,&buffer_pwd)) == 0){ //156 su 5.15, 174 su 4.15
#else
    if((ret = syscall(174,&buffer_path,&buffer_pwd)) == 0){
#endif
        printf("-- Adding of path %s executed successfully ! -- \n", buffer_path);
    } else {
        printf("-- Failed to execute adding path! -- \n");
        perror("\nErrore nella syscall _add_protected_paths"); 
    }

}


void do_remove_path(void){
    char buffer_pwd[100];
    char buffer_path[512];
    int ret, c;
    while(1){
    
        printf("Enter PATH you want to remove from protected paths list\n");
        if (fgets(buffer_path, sizeof(buffer_path),stdin)!=NULL){
            size_t len = strlen(buffer_path);
            if (len > 0 && buffer_path[len-1] == '\n') {
                buffer_path[len-1] = '\0';
            }
        } else {
            printf("Error input command, exit...");
            return;
        }
        // Check if the path is absolute
        if (buffer_path[0] != '/') 
            printf("Error: Path must be absolute\n");
        else{
            if (strlen(buffer_path)==1)
                printf("Error: path is '/' \n");
            else
                break;
        }
    } /*while ((c = getchar()) != '\n' && c != EOF) {
            // Discard characters
        }*/
    printf("Enter password: ");
    if (fgets(buffer_pwd, sizeof(buffer_pwd),stdin)!=NULL){
        size_t len = strlen(buffer_pwd);
        if (len > 0 && buffer_pwd[len-1] == '\n') {
            buffer_pwd[len-1] = '\0';
        }
    } else {
        printf("Error input pwd, exit...");
        return;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    if((ret = syscall(174,&buffer_path,&buffer_pwd)) == 0){
#else
    if((ret = syscall(177,&buffer_path,&buffer_pwd)) == 0){
#endif
        printf("-- Removing of path %s executed successfully ! -- \n", buffer_path);
    } else {
        printf("-- Failed to execute removing path! -- \n");
        perror("\nErrore nella syscall _rm_protected_paths");
    }
}

void do_print_paths(void){
    
    int ret;
    char buffer_pwd[100];
    char* output = (char*)malloc(OUTPUT_BUFFER_SIZE * sizeof(char));
    if (output == NULL){
        printf("Failed to allocate memory user for output");
        return;
    }
    memset(output, 0, OUTPUT_BUFFER_SIZE);
    printf("Enter password: ");
    if (fgets(buffer_pwd, sizeof(buffer_pwd),stdin)!=NULL){
        size_t len = strlen(buffer_pwd);
        if (len > 0 && buffer_pwd[len-1] == '\n') {
            buffer_pwd[len-1] = '\0';
        }
    } else {
        printf("Error input pwd, exit...");
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    if((ret = syscall(177,output,&buffer_pwd)) == 0){
#else
    if((ret = syscall(178,output,&buffer_pwd)) == 0){
#endif
        printf("\n-- Printing of paths executed successfully ! -- \n");
        printf("The existing paths are: \n %s",output);
    } else {
        printf("-- Failed to execute printing paths! -- \n");
        perror("\nErrore nella syscall _print_paths");
    }
}
void select_command(int cmd){
    switch (cmd) {
        case 1: 
            printf("---------------------------------------- \n");
            printf("-- Switching reference monitor state --\n");
            do_switch_state();
            break;
        case 2:
            printf("---------------------------------------- \n");
            printf("-- Adding path to protected list     --\n");
            do_add_path();
            break;
        case 3:
            printf("---------------------------- \n");
            printf("- Removing path from list --\n");
            do_remove_path();
            break;
        case 4:
            printf("---------------------------- \n");
            printf("- Printing protected paths --\n");
            do_print_paths();
            break;
        default:
            printf("---------------------------- \n");
            printf("Invalid command\n");
    }
    return;
}
int main(int argc, char** argv){
    char *cmd_str;
    char *endptr;
    int cmd, c;
    while(1){
        printf("\n The REFERENCE MONITOR is installed ---\n");
        printf("\n Select command that you want to execute ---\n");
        printf("-- 1 --> Change Reference Monitor state  ---\n" 
               "-- 2 --> Add new protected path          ---\n"
               "-- 3 --> Remove path                     ---\n"
               "-- 4 --> Print protected paths list      ---\n"
               "-- 0 --> Exit                            ---\n");
        fgets(cmd_str, sizeof(cmd_str),stdin);
        cmd = strtol(cmd_str, &endptr, 10); //ok, endptr for error
        if (cmd == 0){
            printf("-- Exited successfully -- \n");
            break;
        }
        select_command(cmd);
        //flush stdin per operazioni successive
    } while ((c = getchar()) != '\n' && c != EOF) {
            // flush characters
        }
    return 0;
}