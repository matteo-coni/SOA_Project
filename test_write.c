#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int fd;
    char *path = "reference-monitor/file_test.c"; //

    fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open");
        return EXIT_FAILURE;
    }
    
    if (write(fd, "test", 4) == -1) {
        perror("write");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);
    printf("File written successfully\n");
    return EXIT_SUCCESS;
}
