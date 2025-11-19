// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * crypto_activity_generator.c - Generate crypto activity for testing
 * This program accesses crypto files to generate events for profile testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char **argv) {
    int duration = 5;  /* Default 5 seconds */
    
    if (argc > 1) {
        duration = atoi(argv[1]);
    }
    
    printf("PID: %d\n", getpid());
    printf("Generating crypto activity for %d seconds...\n", duration);
    fflush(stdout);
    
    /* Access crypto files repeatedly */
    for (int i = 0; i < duration * 2; i++) {
        /* Try to access common crypto files */
        int fd = open("/etc/ssl/certs/ca-certificates.crt", O_RDONLY);
        if (fd >= 0) {
            char buf[1024];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
        
        /* Try another cert */
        fd = open("/etc/ssl/certs/ISRG_Root_X1.pem", O_RDONLY);
        if (fd >= 0) {
            char buf[1024];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
        
        /* Small delay */
        usleep(500000);  /* 0.5 seconds */
    }
    
    printf("Crypto activity generation complete\n");
    return 0;
}
