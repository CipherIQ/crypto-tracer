// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * proc_scanner.c - /proc filesystem scanner implementation
 * Implements process discovery, library detection, and open file scanning
 */

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include "include/proc_scanner.h"

/* Initial capacity for dynamic arrays */
#define INITIAL_CAPACITY 16

/* Proc scanner structure */
struct proc_scanner {
    bool verbose;  /* Enable verbose logging */
};

/* Crypto library names to detect */
static const char *crypto_libraries[] = {
    "libssl",
    "libcrypto",
    "libgnutls",
    "libsodium",
    "libnss3",
    "libmbedtls",
    NULL
};

/* Crypto file extensions to detect */
static const char *crypto_extensions[] = {
    ".pem",
    ".crt",
    ".cer",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    NULL
};

/**
 * Check if a string ends with a given suffix
 */
static bool str_ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) {
        return false;
    }
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) {
        return false;
    }
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

/**
 * Check if a path contains a crypto library name
 */
static bool is_crypto_library(const char *path) {
    if (!path) {
        return false;
    }
    
    for (int i = 0; crypto_libraries[i] != NULL; i++) {
        if (strstr(path, crypto_libraries[i]) != NULL) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check if a path is a crypto file based on extension
 */
static bool is_crypto_file(const char *path) {
    if (!path) {
        return false;
    }
    
    for (int i = 0; crypto_extensions[i] != NULL; i++) {
        if (str_ends_with(path, crypto_extensions[i])) {
            return true;
        }
    }
    
    return false;
}

/**
 * Extract library name from full path
 * Example: /usr/lib/x86_64-linux-gnu/libssl.so.1.1 -> libssl
 */
static void extract_library_name(const char *path, char *name, size_t name_size) {
    if (!path || !name || name_size == 0) {
        return;
    }
    
    /* Find the last '/' to get the filename */
    const char *filename = strrchr(path, '/');
    if (filename) {
        filename++;  /* Skip the '/' */
    } else {
        filename = path;
    }
    
    /* Copy up to the first '.' or '-' or end of string */
    size_t i = 0;
    while (i < name_size - 1 && filename[i] != '\0' && 
           filename[i] != '.' && filename[i] != '-') {
        name[i] = filename[i];
        i++;
    }
    name[i] = '\0';
}

/**
 * Read a file into a buffer
 * Returns number of bytes read, or -1 on error
 */
static ssize_t read_file(const char *path, char *buffer, size_t buffer_size) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    
    ssize_t bytes_read = fread(buffer, 1, buffer_size - 1, fp);
    fclose(fp);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
    }
    
    return bytes_read;
}

/**
 * Read /proc/[pid]/comm
 */
static int read_proc_comm(pid_t pid, char *comm, size_t comm_size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    
    ssize_t bytes = read_file(path, comm, comm_size);
    if (bytes <= 0) {
        return -1;
    }
    
    /* Remove trailing newline */
    if (comm[bytes - 1] == '\n') {
        comm[bytes - 1] = '\0';
    }
    
    return 0;
}

/**
 * Read /proc/[pid]/exe
 */
static int read_proc_exe(pid_t pid, char *exe, size_t exe_size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    
    ssize_t bytes = readlink(path, exe, exe_size - 1);
    if (bytes <= 0) {
        return -1;
    }
    
    exe[bytes] = '\0';
    return 0;
}

/**
 * Read /proc/[pid]/cmdline
 */
static int read_proc_cmdline(pid_t pid, char *cmdline, size_t cmdline_size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    
    ssize_t bytes = read_file(path, cmdline, cmdline_size);
    if (bytes <= 0) {
        return -1;
    }
    
    /* Replace null bytes with spaces for readability */
    for (ssize_t i = 0; i < bytes - 1; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    
    return 0;
}

/**
 * Read /proc/[pid]/status to get UID and GID
 */
static int read_proc_status(pid_t pid, uid_t *uid, gid_t *gid) {
    char path[256];
    char buffer[4096];
    
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    
    bool found_uid = false;
    bool found_gid = false;
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strncmp(buffer, "Uid:", 4) == 0) {
            /* Format: Uid: real effective saved fs */
            unsigned int real_uid;
            if (sscanf(buffer + 4, "%u", &real_uid) == 1) {
                *uid = (uid_t)real_uid;
                found_uid = true;
            }
        } else if (strncmp(buffer, "Gid:", 4) == 0) {
            /* Format: Gid: real effective saved fs */
            unsigned int real_gid;
            if (sscanf(buffer + 4, "%u", &real_gid) == 1) {
                *gid = (gid_t)real_gid;
                found_gid = true;
            }
        }
        
        if (found_uid && found_gid) {
            break;
        }
    }
    
    fclose(fp);
    
    return (found_uid && found_gid) ? 0 : -1;
}

/* List management functions */

void process_list_init(process_list_t *list) {
    list->processes = NULL;
    list->count = 0;
    list->capacity = 0;
}

int process_list_add(process_list_t *list, const process_info_t *info) {
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? INITIAL_CAPACITY : list->capacity * 2;
        process_info_t *new_processes = realloc(list->processes, 
                                                 new_capacity * sizeof(process_info_t));
        if (!new_processes) {
            return -1;
        }
        list->processes = new_processes;
        list->capacity = new_capacity;
    }
    
    list->processes[list->count++] = *info;
    return 0;
}

void process_list_free(process_list_t *list) {
    free(list->processes);
    list->processes = NULL;
    list->count = 0;
    list->capacity = 0;
}

void library_list_init(library_list_t *list) {
    list->libraries = NULL;
    list->count = 0;
    list->capacity = 0;
}

int library_list_add(library_list_t *list, const library_info_t *info) {
    /* Check for duplicates */
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->libraries[i].path, info->path) == 0) {
            return 0;  /* Already in list */
        }
    }
    
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? INITIAL_CAPACITY : list->capacity * 2;
        library_info_t *new_libraries = realloc(list->libraries,
                                                 new_capacity * sizeof(library_info_t));
        if (!new_libraries) {
            return -1;
        }
        list->libraries = new_libraries;
        list->capacity = new_capacity;
    }
    
    list->libraries[list->count++] = *info;
    return 0;
}

void library_list_free(library_list_t *list) {
    free(list->libraries);
    list->libraries = NULL;
    list->count = 0;
    list->capacity = 0;
}

void file_list_init(file_list_t *list) {
    list->files = NULL;
    list->count = 0;
    list->capacity = 0;
}

int file_list_add(file_list_t *list, const file_info_t *info) {
    /* Check for duplicates */
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->files[i].path, info->path) == 0) {
            return 0;  /* Already in list */
        }
    }
    
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? INITIAL_CAPACITY : list->capacity * 2;
        file_info_t *new_files = realloc(list->files,
                                          new_capacity * sizeof(file_info_t));
        if (!new_files) {
            return -1;
        }
        list->files = new_files;
        list->capacity = new_capacity;
    }
    
    list->files[list->count++] = *info;
    return 0;
}

void file_list_free(file_list_t *list) {
    free(list->files);
    list->files = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* Proc scanner functions */

proc_scanner_t *proc_scanner_create(void) {
    proc_scanner_t *scanner = malloc(sizeof(proc_scanner_t));
    if (!scanner) {
        return NULL;
    }
    
    scanner->verbose = false;
    return scanner;
}

void proc_scanner_destroy(proc_scanner_t *scanner) {
    free(scanner);
}

int proc_scanner_scan_processes(proc_scanner_t *scanner, process_list_t *processes) {
    if (!scanner || !processes) {
        return -1;
    }
    
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return -1;
    }
    
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Skip non-numeric entries */
        if (!isdigit(entry->d_name[0])) {
            continue;
        }
        
        /* Parse PID */
        char *endptr;
        long pid_long = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid_long <= 0 || pid_long > INT_MAX) {
            continue;
        }
        
        pid_t pid = (pid_t)pid_long;
        process_info_t info;
        
        /* Get process information - handle errors gracefully (Requirement 15.2) */
        if (proc_scanner_get_process_info(scanner, pid, &info) == 0) {
            process_list_add(processes, &info);
        }
        /* Continue scanning even if one process fails */
    }
    
    closedir(proc_dir);
    return 0;
}

int proc_scanner_get_process_info(proc_scanner_t *scanner, pid_t pid, process_info_t *info) {
    if (!scanner || !info) {
        return -1;
    }
    
    memset(info, 0, sizeof(process_info_t));
    info->pid = pid;
    
    /* Read comm - required */
    if (read_proc_comm(pid, info->comm, sizeof(info->comm)) != 0) {
        return -1;  /* Process likely doesn't exist or we don't have permission */
    }
    
    /* Read exe - optional (may fail for kernel threads) */
    if (read_proc_exe(pid, info->exe, sizeof(info->exe)) != 0) {
        strcpy(info->exe, "[unknown]");
    }
    
    /* Read cmdline - optional */
    if (read_proc_cmdline(pid, info->cmdline, sizeof(info->cmdline)) != 0) {
        strcpy(info->cmdline, "");
    }
    
    /* Read UID/GID - optional */
    if (read_proc_status(pid, &info->uid, &info->gid) != 0) {
        info->uid = (uid_t)-1;
        info->gid = (gid_t)-1;
    }
    
    return 0;
}

int proc_scanner_get_loaded_libraries(proc_scanner_t *scanner, pid_t pid, library_list_t *libs) {
    if (!scanner || !libs) {
        return -1;
    }
    
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;  /* Process doesn't exist or no permission */
    }
    
    char line[MAX_PATH_LEN];
    while (fgets(line, sizeof(line), fp)) {
        /* Parse maps line format:
         * address perms offset dev inode pathname
         * Example: 7f1234567000-7f1234568000 r-xp 00000000 08:01 12345 /usr/lib/libssl.so.1.1
         */
        
        /* Find the pathname (after the 5th whitespace) */
        char *pathname = line;
        int spaces = 0;
        while (*pathname && spaces < 5) {
            if (isspace(*pathname)) {
                spaces++;
                while (isspace(*pathname)) {
                    pathname++;
                }
            } else {
                pathname++;
            }
        }
        
        /* Remove trailing newline */
        size_t len = strlen(pathname);
        if (len > 0 && pathname[len - 1] == '\n') {
            pathname[len - 1] = '\0';
        }
        
        /* Check if this is a crypto library */
        if (strlen(pathname) > 0 && is_crypto_library(pathname)) {
            library_info_t lib_info;
            strncpy(lib_info.path, pathname, sizeof(lib_info.path) - 1);
            lib_info.path[sizeof(lib_info.path) - 1] = '\0';
            
            extract_library_name(pathname, lib_info.name, sizeof(lib_info.name));
            
            library_list_add(libs, &lib_info);
        }
    }
    
    fclose(fp);
    return 0;
}

int proc_scanner_get_open_files(proc_scanner_t *scanner, pid_t pid, file_list_t *files) {
    if (!scanner || !files) {
        return -1;
    }
    
    char fd_dir_path[256];
    snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
    
    DIR *fd_dir = opendir(fd_dir_path);
    if (!fd_dir) {
        return -1;  /* Process doesn't exist or no permission */
    }
    
    struct dirent *entry;
    while ((entry = readdir(fd_dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        /* Build path to fd symlink */
        char fd_link_path[512];
        snprintf(fd_link_path, sizeof(fd_link_path), "%s/%s", fd_dir_path, entry->d_name);
        
        /* Read the symlink to get the actual file path */
        char file_path[MAX_PATH_LEN];
        ssize_t link_len = readlink(fd_link_path, file_path, sizeof(file_path) - 1);
        if (link_len <= 0) {
            continue;  /* Failed to read symlink */
        }
        file_path[link_len] = '\0';
        
        /* Check if this is a crypto file */
        if (is_crypto_file(file_path)) {
            file_info_t file_info;
            strncpy(file_info.path, file_path, sizeof(file_info.path) - 1);
            file_info.path[sizeof(file_info.path) - 1] = '\0';
            
            /* Parse FD number */
            char *endptr;
            long fd_long = strtol(entry->d_name, &endptr, 10);
            if (*endptr == '\0' && fd_long >= 0 && fd_long <= INT_MAX) {
                file_info.fd = (int)fd_long;
            } else {
                file_info.fd = -1;
            }
            
            file_list_add(files, &file_info);
        }
    }
    
    closedir(fd_dir);
    return 0;
}
