// Simple C program that directly accesses crypto files
// No child processes - does the work itself

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    printf("Direct crypto access test\n");
    printf("PID: %d\n", getpid());
    fflush(stdout);
    
    // Loop and directly access crypto files
    for (int i = 0; i < 20; i++) {
        int fd = open("/etc/ssl/certs/ca-certificates.crt", O_RDONLY);
        if (fd >= 0) {
            char buf[1024];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
        usleep(500000);  // 0.5 seconds
    }
    
    return 0;
}
