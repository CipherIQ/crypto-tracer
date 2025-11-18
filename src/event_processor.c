// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * event_processor.c - Event processing pipeline implementation
 * Implements event filtering with AND logic and early termination
 * Requirements: 14.3, 14.4
 */

/* Enable POSIX features for strdup and readlink */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fnmatch.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include "include/event_processor.h"
#include "include/privacy_filter.h"
#include "include/logger.h"
#include "ebpf/common.h"

/**
 * Create a new filter set
 * Returns pointer to filter set, or NULL on failure
 */
filter_set_t *filter_set_create(void) {
    filter_set_t *set = (filter_set_t *)calloc(1, sizeof(filter_set_t));
    if (!set) {
        log_error("Failed to allocate filter set");
        return NULL;
    }
    
    set->filters = NULL;
    set->count = 0;
    
    return set;
}

/**
 * Add a filter to the filter set
 * 
 * @param set Filter set
 * @param type Filter type
 * @param value Filter value (type depends on filter type)
 * @return 0 on success, -1 on failure
 */
int filter_set_add(filter_set_t *set, filter_type_t type, const void *value) {
    filter_t *filter = NULL;
    
    if (!set || !value) {
        return -1;
    }
    
    /* Allocate new filter */
    filter = (filter_t *)calloc(1, sizeof(filter_t));
    if (!filter) {
        log_error("Failed to allocate filter");
        return -1;
    }
    
    filter->type = type;
    filter->next = NULL;
    
    /* Set filter value based on type */
    switch (type) {
        case FILTER_TYPE_PID:
            filter->value.pid = *(int *)value;
            break;
            
        case FILTER_TYPE_PROCESS_NAME:
            filter->value.name_pattern = strdup((const char *)value);
            if (!filter->value.name_pattern) {
                free(filter);
                return -1;
            }
            break;
            
        case FILTER_TYPE_LIBRARY:
            filter->value.library_pattern = strdup((const char *)value);
            if (!filter->value.library_pattern) {
                free(filter);
                return -1;
            }
            break;
            
        case FILTER_TYPE_FILE_PATH:
            filter->value.file_pattern = strdup((const char *)value);
            if (!filter->value.file_pattern) {
                free(filter);
                return -1;
            }
            break;
            
        default:
            free(filter);
            return -1;
    }
    
    /* Add to linked list */
    filter->next = set->filters;
    set->filters = filter;
    set->count++;
    
    return 0;
}

/**
 * Perform glob pattern matching
 * Uses fnmatch for glob pattern support
 * 
 * @param pattern Glob pattern (e.g., "/etc/ssl/ *.pem")
 * @param string String to match against
 * @return true if matches, false otherwise
 */
bool glob_match(const char *pattern, const char *string) {
    if (!pattern || !string) {
        return false;
    }
    
    /* Use fnmatch with FNM_PATHNAME for path-aware matching */
    return (fnmatch(pattern, string, FNM_PATHNAME) == 0);
}

/**
 * Perform substring matching (case-insensitive)
 * 
 * @param pattern Substring pattern
 * @param string String to search in
 * @return true if pattern is found in string, false otherwise
 */
bool substring_match(const char *pattern, const char *string) {
    size_t pattern_len, string_len, i, j;
    
    if (!pattern || !string) {
        return false;
    }
    
    pattern_len = strlen(pattern);
    string_len = strlen(string);
    
    if (pattern_len == 0) {
        return true;  /* Empty pattern matches everything */
    }
    
    if (pattern_len > string_len) {
        return false;
    }
    
    /* Case-insensitive substring search */
    for (i = 0; i <= string_len - pattern_len; i++) {
        for (j = 0; j < pattern_len; j++) {
            if (tolower((unsigned char)string[i + j]) != tolower((unsigned char)pattern[j])) {
                break;
            }
        }
        if (j == pattern_len) {
            return true;  /* Found match */
        }
    }
    
    return false;
}

/**
 * Check if a single filter matches an event
 * Requirement: 14.3 - Early termination for performance
 * 
 * @param filter Filter to check
 * @param event Event to match against
 * @return true if filter matches, false otherwise
 */
static bool filter_matches_event(filter_t *filter, processed_event_t *event) {
    if (!filter || !event) {
        return false;
    }
    
    switch (filter->type) {
        case FILTER_TYPE_PID:
            /* Match PID exactly */
            return (event->pid == (uint32_t)filter->value.pid);
            
        case FILTER_TYPE_PROCESS_NAME:
            /* Substring match on process name */
            if (event->process) {
                return substring_match(filter->value.name_pattern, event->process);
            }
            return false;
            
        case FILTER_TYPE_LIBRARY:
            /* Substring match on library path or library name */
            if (event->library) {
                if (substring_match(filter->value.library_pattern, event->library)) {
                    return true;
                }
            }
            if (event->library_name) {
                if (substring_match(filter->value.library_pattern, event->library_name)) {
                    return true;
                }
            }
            return false;
            
        case FILTER_TYPE_FILE_PATH:
            /* Glob pattern match on file path */
            if (event->file) {
                return glob_match(filter->value.file_pattern, event->file);
            }
            return false;
            
        default:
            return false;
    }
}

/**
 * Check if event matches all filters in the set
 * Requirement: 14.4 - AND logic with early termination
 * Requirement: 14.3 - Optimize to under 1 microsecond per event
 * 
 * @param set Filter set
 * @param event Event to match
 * @return true if all filters match (or no filters), false otherwise
 */
bool filter_set_matches(filter_set_t *set, processed_event_t *event) {
    filter_t *filter = NULL;
    
    if (!set || !event) {
        return false;
    }
    
    /* No filters means match everything */
    if (set->count == 0 || !set->filters) {
        return true;
    }
    
    /* AND logic: All filters must match */
    /* Early termination: Return false as soon as one filter doesn't match */
    for (filter = set->filters; filter != NULL; filter = filter->next) {
        if (!filter_matches_event(filter, event)) {
            return false;  /* Early termination */
        }
    }
    
    return true;  /* All filters matched */
}

/**
 * Destroy filter set and free all resources
 * 
 * @param set Filter set to destroy
 */
void filter_set_destroy(filter_set_t *set) {
    filter_t *filter = NULL;
    filter_t *next = NULL;
    
    if (!set) {
        return;
    }
    
    /* Free all filters in the linked list */
    filter = set->filters;
    while (filter) {
        next = filter->next;
        
        /* Free filter value based on type */
        switch (filter->type) {
            case FILTER_TYPE_PROCESS_NAME:
                free(filter->value.name_pattern);
                break;
            case FILTER_TYPE_LIBRARY:
                free(filter->value.library_pattern);
                break;
            case FILTER_TYPE_FILE_PATH:
                free(filter->value.file_pattern);
                break;
            case FILTER_TYPE_PID:
                /* No dynamic allocation for PID */
                break;
        }
        
        free(filter);
        filter = next;
    }
    
    free(set);
}

/**
 * Create a new event processor
 * 
 * @param args CLI arguments for configuration
 * @return Pointer to event processor, or NULL on failure
 */
event_processor_t *event_processor_create(cli_args_t *args) {
    event_processor_t *proc = NULL;
    
    if (!args) {
        return NULL;
    }
    
    /* Allocate processor structure */
    proc = (event_processor_t *)calloc(1, sizeof(event_processor_t));
    if (!proc) {
        log_error("Failed to allocate event processor");
        return NULL;
    }
    
    /* Create filter set */
    proc->filters = filter_set_create();
    if (!proc->filters) {
        free(proc);
        return NULL;
    }
    
    proc->args = args;
    proc->redact_paths = !args->no_redact;
    
    /* Add filters based on CLI arguments */
    if (args->pid > 0) {
        if (event_processor_add_filter(proc, FILTER_TYPE_PID, &args->pid) != 0) {
            event_processor_destroy(proc);
            return NULL;
        }
    }
    
    if (args->process_name) {
        if (event_processor_add_filter(proc, FILTER_TYPE_PROCESS_NAME, args->process_name) != 0) {
            event_processor_destroy(proc);
            return NULL;
        }
    }
    
    if (args->library_filter) {
        if (event_processor_add_filter(proc, FILTER_TYPE_LIBRARY, args->library_filter) != 0) {
            event_processor_destroy(proc);
            return NULL;
        }
    }
    
    if (args->file_filter) {
        if (event_processor_add_filter(proc, FILTER_TYPE_FILE_PATH, args->file_filter) != 0) {
            event_processor_destroy(proc);
            return NULL;
        }
    }
    
    return proc;
}

/**
 * Add a filter to the event processor
 * 
 * @param proc Event processor
 * @param type Filter type
 * @param value Filter value
 * @return 0 on success, -1 on failure
 */
int event_processor_add_filter(event_processor_t *proc, filter_type_t type, const void *value) {
    if (!proc || !proc->filters) {
        return -1;
    }
    
    return filter_set_add(proc->filters, type, value);
}

/**
 * Check if event matches all filters
 * 
 * @param proc Event processor
 * @param event Event to check
 * @return true if event matches all filters, false otherwise
 */
bool event_processor_matches_filters(event_processor_t *proc, processed_event_t *event) {
    if (!proc || !proc->filters) {
        return false;
    }
    
    return filter_set_matches(proc->filters, event);
}

/**
 * Destroy event processor and free all resources
 * 
 * @param proc Event processor to destroy
 */
void event_processor_destroy(event_processor_t *proc) {
    if (!proc) {
        return;
    }
    
    if (proc->filters) {
        filter_set_destroy(proc->filters);
    }
    
    free(proc);
}


/**
 * Read process name from /proc/[pid]/comm
 * Requirement: 17.3
 * 
 * @param pid Process ID
 * @param process_name Output pointer for process name (caller must free)
 * @return 0 on success, -1 on failure
 */
int enrich_process_name(pid_t pid, char **process_name) {
    char path[64];
    FILE *fp = NULL;
    char buffer[256];
    size_t len;
    
    if (!process_name) {
        return -1;
    }
    
    *process_name = NULL;
    
    /* Build path to /proc/[pid]/comm */
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    
    /* Open file */
    fp = fopen(path, "r");
    if (!fp) {
        /* Process may have exited or we don't have permission */
        return -1;
    }
    
    /* Read process name */
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    
    /* Remove trailing newline */
    len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    
    /* Allocate and copy */
    *process_name = strdup(buffer);
    if (!*process_name) {
        return -1;
    }
    
    return 0;
}

/**
 * Read executable path from /proc/[pid]/exe
 * Requirement: 17.4
 * 
 * @param pid Process ID
 * @param exe_path Output pointer for executable path (caller must free)
 * @return 0 on success, -1 on failure
 */
int enrich_executable_path(pid_t pid, char **exe_path) {
    char path[64];
    char buffer[1024];
    ssize_t len;
    
    if (!exe_path) {
        return -1;
    }
    
    *exe_path = NULL;
    
    /* Build path to /proc/[pid]/exe */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    
    /* Read symlink */
    len = readlink(path, buffer, sizeof(buffer) - 1);
    if (len < 0) {
        /* Process may have exited or we don't have permission */
        return -1;
    }
    
    buffer[len] = '\0';
    
    /* Allocate and copy */
    *exe_path = strdup(buffer);
    if (!*exe_path) {
        return -1;
    }
    
    return 0;
}

/**
 * Read command line from /proc/[pid]/cmdline
 * Requirement: 17.4
 * 
 * @param pid Process ID
 * @param cmdline Output pointer for command line (caller must free)
 * @return 0 on success, -1 on failure
 */
int enrich_cmdline(pid_t pid, char **cmdline) {
    char path[64];
    FILE *fp = NULL;
    char buffer[4096];
    size_t bytes_read;
    size_t i;
    
    if (!cmdline) {
        return -1;
    }
    
    *cmdline = NULL;
    
    /* Build path to /proc/[pid]/cmdline */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    
    /* Open file */
    fp = fopen(path, "r");
    if (!fp) {
        /* Process may have exited or we don't have permission */
        return -1;
    }
    
    /* Read command line (arguments are separated by null bytes) */
    bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);
    
    if (bytes_read == 0) {
        return -1;
    }
    
    buffer[bytes_read] = '\0';
    
    /* Replace null bytes with spaces for readability */
    for (i = 0; i < bytes_read - 1; i++) {
        if (buffer[i] == '\0') {
            buffer[i] = ' ';
        }
    }
    
    /* Allocate and copy */
    *cmdline = strdup(buffer);
    if (!*cmdline) {
        return -1;
    }
    
    return 0;
}

/**
 * Enrich event with process metadata from /proc
 * Requirements: 17.3, 17.4, 17.5, 17.6
 * 
 * @param event Event to enrich
 * @return 0 on success, -1 on failure (partial enrichment may occur)
 */
int enrich_event(processed_event_t *event) {
    char *process_name = NULL;
    char *exe_path = NULL;
    char *cmdline_str = NULL;
    int enriched = 0;
    
    if (!event) {
        return -1;
    }
    
    /* Enrich process name if not already set */
    if (!event->process && event->pid > 0) {
        if (enrich_process_name(event->pid, &process_name) == 0) {
            event->process = process_name;
            enriched++;
        }
    }
    
    /* Enrich executable path if not already set */
    if (!event->exe && event->pid > 0) {
        if (enrich_executable_path(event->pid, &exe_path) == 0) {
            event->exe = exe_path;
            enriched++;
        }
    }
    
    /* Enrich command line if not already set and this is a process_exec event */
    if (!event->cmdline && event->pid > 0 && event->event_type && 
        strcmp(event->event_type, "process_exec") == 0) {
        if (enrich_cmdline(event->pid, &cmdline_str) == 0) {
            event->cmdline = cmdline_str;
            enriched++;
        }
    }
    
    /* Requirement 17.6: Handle missing /proc data gracefully */
    /* Return success even if some enrichment failed */
    return 0;
}


/**
 * Check if string ends with suffix (case-insensitive)
 */
static bool str_ends_with(const char *str, const char *suffix) {
    size_t str_len, suffix_len, i;
    
    if (!str || !suffix) {
        return false;
    }
    
    str_len = strlen(str);
    suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) {
        return false;
    }
    
    /* Compare from the end, case-insensitive */
    for (i = 0; i < suffix_len; i++) {
        if (tolower((unsigned char)str[str_len - suffix_len + i]) != 
            tolower((unsigned char)suffix[i])) {
            return false;
        }
    }
    
    return true;
}

/**
 * Classify cryptographic file by extension and content
 * Requirement: 17.1
 * 
 * For v1.0: Simplified classification based on extension only
 * .pem files are classified as "certificate" by default
 * 
 * @param path File path
 * @return File type classification
 */
file_type_t classify_crypto_file(const char *path) {
    if (!path) {
        return FILE_TYPE_UNKNOWN;
    }
    
    /* Check for certificate extensions */
    if (str_ends_with(path, ".crt") || 
        str_ends_with(path, ".cer") ||
        str_ends_with(path, ".pem")) {
        /* Requirement: For .pem files, classify as "certificate" by default (v1.0 simplification) */
        return FILE_TYPE_CERTIFICATE;
    }
    
    /* Check for private key extensions */
    if (str_ends_with(path, ".key")) {
        return FILE_TYPE_PRIVATE_KEY;
    }
    
    /* Check for keystore extensions */
    if (str_ends_with(path, ".p12") ||
        str_ends_with(path, ".pfx") ||
        str_ends_with(path, ".jks") ||
        str_ends_with(path, ".keystore")) {
        return FILE_TYPE_KEYSTORE;
    }
    
    return FILE_TYPE_UNKNOWN;
}

/**
 * Convert file type enum to string
 * 
 * @param type File type
 * @return String representation
 */
const char *file_type_to_string(file_type_t type) {
    switch (type) {
        case FILE_TYPE_CERTIFICATE:
            return "certificate";
        case FILE_TYPE_PRIVATE_KEY:
            return "private_key";
        case FILE_TYPE_KEYSTORE:
            return "keystore";
        case FILE_TYPE_UNKNOWN:
        default:
            return "unknown";
    }
}

/**
 * Extract library name from full path
 * Requirement: 17.2
 * 
 * Examples:
 *   /usr/lib/libssl.so.1.1 -> libssl
 *   /lib/x86_64-linux-gnu/libcrypto.so.3 -> libcrypto
 * 
 * @param library_path Full library path
 * @return Library name (caller must free), or NULL on failure
 */
char *extract_library_name(const char *library_path) {
    const char *filename = NULL;
    const char *dot = NULL;
    size_t name_len;
    char *library_name = NULL;
    
    if (!library_path) {
        return NULL;
    }
    
    /* Find the last '/' to get filename */
    filename = strrchr(library_path, '/');
    if (filename) {
        filename++;  /* Skip the '/' */
    } else {
        filename = library_path;  /* No path, just filename */
    }
    
    /* Find the first '.' to remove version suffix */
    dot = strchr(filename, '.');
    if (dot) {
        name_len = dot - filename;
    } else {
        name_len = strlen(filename);
    }
    
    /* Allocate and copy library name */
    library_name = (char *)malloc(name_len + 1);
    if (!library_name) {
        return NULL;
    }
    
    strncpy(library_name, filename, name_len);
    library_name[name_len] = '\0';
    
    return library_name;
}

/**
 * Apply privacy filtering to event paths
 * Requirements: 6.1, 6.2, 6.3, 6.4
 * 
 * @param event Event to filter
 * @param redact_enabled Whether redaction is enabled (false if --no-redact)
 * @return 0 on success, -1 on failure
 */
int apply_privacy_filter(processed_event_t *event, bool redact_enabled) {
    char *filtered_path = NULL;
    char *filtered_cmdline = NULL;
    
    if (!event) {
        return -1;
    }
    
    /* Filter file path if present */
    if (event->file) {
        filtered_path = privacy_filter_path(event->file, redact_enabled);
        if (filtered_path) {
            free(event->file);
            event->file = filtered_path;
        } else {
            /* If filtering failed, keep original but log warning */
            log_warn("Failed to filter file path");
        }
    }
    
    /* Filter library path if present */
    if (event->library) {
        filtered_path = privacy_filter_path(event->library, redact_enabled);
        if (filtered_path) {
            free(event->library);
            event->library = filtered_path;
        } else {
            log_warn("Failed to filter library path");
        }
    }
    
    /* Filter executable path if present */
    if (event->exe) {
        filtered_path = privacy_filter_path(event->exe, redact_enabled);
        if (filtered_path) {
            free(event->exe);
            event->exe = filtered_path;
        } else {
            log_warn("Failed to filter exe path");
        }
    }
    
    /* Filter command line if present */
    if (event->cmdline) {
        filtered_cmdline = privacy_filter_cmdline(event->cmdline, redact_enabled);
        if (filtered_cmdline) {
            free(event->cmdline);
            event->cmdline = filtered_cmdline;
        } else {
            log_warn("Failed to filter cmdline");
        }
    }
    
    return 0;
}
