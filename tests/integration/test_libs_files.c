// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * Test program for libs and files commands
 * Generates crypto file access and library loading events
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

int main() {
    printf("Test program PID: %d\n", getpid());
    printf("Generating crypto file access and library loading events...\n");
    fflush(stdout);
    
    /* Test 1: Access crypto files */
    printf("\n1. Accessing crypto files...\n");
    
    const char *crypto_files[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-bundle.crt",
        NULL
    };
    
    for (int i = 0; crypto_files[i] != NULL; i++) {
        int fd = open(crypto_files[i], O_RDONLY);
        if (fd >= 0) {
            printf("   Opened: %s\n", crypto_files[i]);
            char buf[1024];
            read(fd, buf, sizeof(buf));
            close(fd);
        } else {
            printf("   Failed to open: %s\n", crypto_files[i]);
        }
        sleep(1);
    }
    
    /* Test 2: Load crypto libraries */
    printf("\n2. Loading crypto libraries...\n");
    
    const char *crypto_libs[] = {
        "libssl.so.3",
        "libcrypto.so.3",
        NULL
    };
    
    for (int i = 0; crypto_libs[i] != NULL; i++) {
        void *handle = dlopen(crypto_libs[i], RTLD_LAZY);
        if (handle) {
            printf("   Loaded: %s\n", crypto_libs[i]);
            /* Keep library loaded for a moment */
            sleep(1);
            dlclose(handle);
        } else {
            printf("   Failed to load: %s - %s\n", crypto_libs[i], dlerror());
        }
    }
    
    printf("\nTest complete\n");
    return 0;
}
