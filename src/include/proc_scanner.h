// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * proc_scanner.h - /proc filesystem scanner interface
 * Provides process discovery, library detection, and open file scanning
 */

#ifndef __PROC_SCANNER_H__
#define __PROC_SCANNER_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* Maximum path length for files and libraries */
#define MAX_PATH_LEN 4096

/* Maximum command line length */
#define MAX_CMDLINE_LEN 4096

/* Process information structure */
typedef struct {
    pid_t pid;
    char comm[256];           /* Process name from /proc/[pid]/comm */
    char exe[MAX_PATH_LEN];   /* Executable path from /proc/[pid]/exe */
    char cmdline[MAX_CMDLINE_LEN]; /* Command line from /proc/[pid]/cmdline */
    uid_t uid;
    gid_t gid;
} process_info_t;

/* Library information structure */
typedef struct {
    char path[MAX_PATH_LEN];
    char name[256];           /* Extracted library name */
} library_info_t;

/* File information structure */
typedef struct {
    char path[MAX_PATH_LEN];
    int fd;                   /* File descriptor number */
} file_info_t;

/* Dynamic array for process list */
typedef struct {
    process_info_t *processes;
    size_t count;
    size_t capacity;
} process_list_t;

/* Dynamic array for library list */
typedef struct {
    library_info_t *libraries;
    size_t count;
    size_t capacity;
} library_list_t;

/* Dynamic array for file list */
typedef struct {
    file_info_t *files;
    size_t count;
    size_t capacity;
} file_list_t;

/* Proc scanner opaque structure */
typedef struct proc_scanner proc_scanner_t;

/**
 * Create a new proc scanner instance
 * Returns: Pointer to proc_scanner_t on success, NULL on failure
 */
proc_scanner_t *proc_scanner_create(void);

/**
 * Scan all running processes
 * Requirements: 3.1, 15.2
 * 
 * @param scanner Proc scanner instance
 * @param processes Output list of processes
 * @return 0 on success, -1 on failure
 */
int proc_scanner_scan_processes(proc_scanner_t *scanner, process_list_t *processes);

/**
 * Get detailed information about a specific process
 * Requirements: 3.1, 15.2
 * 
 * @param scanner Proc scanner instance
 * @param pid Process ID to query
 * @param info Output process information
 * @return 0 on success, -1 on failure (e.g., process doesn't exist)
 */
int proc_scanner_get_process_info(proc_scanner_t *scanner, pid_t pid, process_info_t *info);

/**
 * Get list of loaded libraries for a process
 * Requirements: 3.2, 4.1, 4.2, 15.2
 * 
 * Scans /proc/[pid]/maps for crypto libraries:
 * - libssl, libcrypto, libgnutls, libsodium, libnss3, libmbedtls
 * 
 * @param scanner Proc scanner instance
 * @param pid Process ID to query
 * @param libs Output list of libraries
 * @return 0 on success, -1 on failure
 */
int proc_scanner_get_loaded_libraries(proc_scanner_t *scanner, pid_t pid, library_list_t *libs);

/**
 * Get list of open crypto files for a process
 * Requirements: 3.3, 4.3, 15.2
 * 
 * Scans /proc/[pid]/fd/ for crypto files:
 * - .pem, .crt, .cer, .key, .p12, .pfx, .jks, .keystore
 * 
 * @param scanner Proc scanner instance
 * @param pid Process ID to query
 * @param files Output list of open files
 * @return 0 on success, -1 on failure
 */
int proc_scanner_get_open_files(proc_scanner_t *scanner, pid_t pid, file_list_t *files);

/**
 * Destroy proc scanner instance and free resources
 * 
 * @param scanner Proc scanner instance to destroy
 */
void proc_scanner_destroy(proc_scanner_t *scanner);

/* Helper functions for list management */

/**
 * Initialize a process list
 */
void process_list_init(process_list_t *list);

/**
 * Add a process to the list
 * Returns 0 on success, -1 on failure
 */
int process_list_add(process_list_t *list, const process_info_t *info);

/**
 * Free process list resources
 */
void process_list_free(process_list_t *list);

/**
 * Initialize a library list
 */
void library_list_init(library_list_t *list);

/**
 * Add a library to the list
 * Returns 0 on success, -1 on failure
 */
int library_list_add(library_list_t *list, const library_info_t *info);

/**
 * Free library list resources
 */
void library_list_free(library_list_t *list);

/**
 * Initialize a file list
 */
void file_list_init(file_list_t *list);

/**
 * Add a file to the list
 * Returns 0 on success, -1 on failure
 */
int file_list_add(file_list_t *list, const file_info_t *info);

/**
 * Free file list resources
 */
void file_list_free(file_list_t *list);

#endif /* __PROC_SCANNER_H__ */
