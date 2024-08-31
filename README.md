# SOA Project 2023/2024
## Kernel Level Reference Monitor for File Protection

This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:
- OFF, meaning that its operations are currently disabled;
- ON, meaning that its operations are currently enabled;
- REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode).
The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

- the process TGID, the thread ID, the user-id, the effective user-id, the program path-name that is currently attempting the open, a cryptographic hash of the program file content.
  
The computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work.

### Installation
- Clone the repo and enter in the main directory
  ```sh
  git clone https://github.com/matteo-coni/SOA_Project.git
  ```
  ```sh
  cd SOA_Project
  ```
- Build the project
  ```sh
  make all
  ```
- Install the modules by entering the password
  ```sh
  make mount
  ```

### Usage
To use the reference monitor, you can start the program user.o with sudo
  ```sh
  sudo ./user.o
  ```
There are four options:
* 1 - **Switch State**: you can choose between OFF, REC_OFF, ON, REC_ON
* 2 - **Add new path** to the protected paths list
* 3 - **Remove path** from the protected paths list
* 4 - **Print** protected paths list

To execute the  'Switch state', 'Add new path' and 'Remove path' command you must enter the reference monitor password.
Also, to execute the 'Add new path' and 'Remove path' command the reference monitor must be in REC_ON or ON state.

In addition, there is a file called 'test_write.o' that try to open and write the string 'test' on the file '.../SOA_Project/reference-monitor/file_test.c'. Run it with
```sh
  sudo ./test_write.o
  ```
### Actions blocked
When the state of the reference monitor is ON or REC_ON, the following actions on the protected files come blocked by one of the new installed kretprobes:
* **vfs_open_retprobe**: denies write access to protected files
* **delete_retprobe**: denies deletion of protected files or directories
* **security_mkdir_retprobe**: denies the creation of directories in protected directories
* **security_inode_create_retprobe**: denies the creation of file in protected directories
* **security_inode_link_retprobe**: blocks link generation of a protected file or link generation of a file in a protected directory
* **security_inode_symlink_retprobe**: blocks sym_link generation of a protected file
* **security_inode_unlink_retprobe**: blocks the remove of a protected file hard link

Each kretprobe is associated with a handler for handling the call. If the file is in the protected list, the value 0 is returned and the post_handler is executed, where the collect_info() function is called.
In this function, the information to be written to the log file is collected and the handler for 'deferred work' is placed in the appropriate queue.

