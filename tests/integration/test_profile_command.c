// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_profile_command.c - Integration test for profile command
 * Tests profile command functionality with a real process
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <dlfcn.h>

/**
 * Test process that performs crypto operations
 */
static void test_crypto_process(void) {
    /* Try to load a crypto library */
    void *handle = dlopen("libssl.so.3", RTLD_LAZY);
    if (!handle) {
        handle = dlopen("libssl.so.1.1", RTLD_LAZY);
    }
    if (!handle) {
        handle = dlopen("libssl.so", RTLD_LAZY);
    }
    
    if (handle) {
        printf("Loaded crypto library\n");
        fflush(stdout);
    }
    
    /* Try to open a crypto file */
    FILE *f = fopen("/etc/ssl/certs/ca-certificates.crt", "r");
    if (f) {
        printf("Opened crypto file\n");
        fclose(f);
        fflush(stdout);
    }
    
    /* Sleep to allow profiling */
    sleep(5);
    
    if (handle) {
        dlclose(handle);
    }
}

int main(int argc, char **argv) {
    pid_t child_pid;
    int status;
    
    printf("=== Profile Command Integration Test ===\n\n");
    
    /* Fork a child process to profile */
    child_pid = fork();
    
    if (child_pid < 0) {
        perror("fork");
        return 1;
    }
    
    if (child_pid == 0) {
        /* Child process - perform crypto operations */
        test_crypto_process();
        exit(0);
    }
    
    /* Parent process - run crypto-tracer profile command */
    printf("Child PID: %d\n", child_pid);
    printf("Running profile command...\n\n");
    
    /* Build command */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), 
             "sudo ./build/crypto-tracer profile --pid %d --duration 3 --format json-pretty",
             child_pid);
    
    /* Execute profile command */
    int ret = system(cmd);
    
    /* Wait for child to complete */
    waitpid(child_pid, &status, 0);
    
    printf("\n=== Test Complete ===\n");
    
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("Child process exited successfully\n");
    }
    
    if (ret == 0) {
        printf("Profile command executed successfully\n");
        return 0;
    } else {
        printf("Profile command failed\n");
        return 1;
    }
}
