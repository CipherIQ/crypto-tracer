// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_proc_scanner_demo.c - Demonstration of proc scanner functionality
 * This is a simple demo program to show the proc scanner in action
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "proc_scanner.h"

int main(void) {
    printf("=== Proc Scanner Demonstration ===\n\n");
    
    /* Create scanner */
    proc_scanner_t *scanner = proc_scanner_create();
    if (!scanner) {
        fprintf(stderr, "Failed to create proc scanner\n");
        return 1;
    }
    
    /* Test 1: Get info for current process */
    printf("Test 1: Current Process Information\n");
    printf("------------------------------------\n");
    pid_t self_pid = getpid();
    process_info_t self_info;
    
    if (proc_scanner_get_process_info(scanner, self_pid, &self_info) == 0) {
        printf("PID: %d\n", self_info.pid);
        printf("Name: %s\n", self_info.comm);
        printf("Executable: %s\n", self_info.exe);
        printf("Command line: %s\n", self_info.cmdline);
        printf("UID: %u, GID: %u\n", self_info.uid, self_info.gid);
    } else {
        printf("Failed to get process info\n");
    }
    printf("\n");
    
    /* Test 2: Scan all processes */
    printf("Test 2: Process Discovery\n");
    printf("-------------------------\n");
    process_list_t processes;
    process_list_init(&processes);
    
    if (proc_scanner_scan_processes(scanner, &processes) == 0) {
        printf("Found %zu processes\n", processes.count);
        printf("First 5 processes:\n");
        for (size_t i = 0; i < processes.count && i < 5; i++) {
            printf("  PID %d: %s\n", 
                   processes.processes[i].pid,
                   processes.processes[i].comm);
        }
    } else {
        printf("Failed to scan processes\n");
    }
    process_list_free(&processes);
    printf("\n");
    
    /* Test 3: Get loaded libraries for current process */
    printf("Test 3: Loaded Libraries\n");
    printf("------------------------\n");
    library_list_t libs;
    library_list_init(&libs);
    
    if (proc_scanner_get_loaded_libraries(scanner, self_pid, &libs) == 0) {
        if (libs.count > 0) {
            printf("Found %zu crypto libraries:\n", libs.count);
            for (size_t i = 0; i < libs.count; i++) {
                printf("  %s: %s\n", 
                       libs.libraries[i].name,
                       libs.libraries[i].path);
            }
        } else {
            printf("No crypto libraries loaded in this process\n");
        }
    } else {
        printf("Failed to get loaded libraries\n");
    }
    library_list_free(&libs);
    printf("\n");
    
    /* Test 4: Get open crypto files for current process */
    printf("Test 4: Open Crypto Files\n");
    printf("-------------------------\n");
    file_list_t files;
    file_list_init(&files);
    
    if (proc_scanner_get_open_files(scanner, self_pid, &files) == 0) {
        if (files.count > 0) {
            printf("Found %zu open crypto files:\n", files.count);
            for (size_t i = 0; i < files.count; i++) {
                printf("  FD %d: %s\n",
                       files.files[i].fd,
                       files.files[i].path);
            }
        } else {
            printf("No crypto files open in this process\n");
        }
    } else {
        printf("Failed to get open files\n");
    }
    file_list_free(&files);
    printf("\n");
    
    /* Cleanup */
    proc_scanner_destroy(scanner);
    
    printf("=== Demonstration Complete ===\n");
    return 0;
}
