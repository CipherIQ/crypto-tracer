// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * crypto_tracer.h - Main header for crypto-tracer
 * Core definitions, exit codes, and function prototypes
 */

#ifndef __CRYPTO_TRACER_H__
#define __CRYPTO_TRACER_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/* Version information */
#define CRYPTO_TRACER_VERSION "1.0.0"

/* Exit codes */
#define EXIT_SUCCESS 0
#define EXIT_GENERAL_ERROR 1
#define EXIT_ARGUMENT_ERROR 2
#define EXIT_PRIVILEGE_ERROR 3
#define EXIT_KERNEL_ERROR 4
#define EXIT_BPF_ERROR 5

/* Command types */
typedef enum {
    CMD_NONE = 0,
    CMD_MONITOR,
    CMD_PROFILE,
    CMD_SNAPSHOT,
    CMD_LIBS,
    CMD_FILES,
    CMD_HELP,
    CMD_VERSION
} command_type_t;

/* Output format types */
typedef enum {
    FORMAT_JSON_STREAM = 0,
    FORMAT_JSON_ARRAY,
    FORMAT_JSON_PRETTY,
    FORMAT_SUMMARY
} output_format_t;

/* Command-line arguments structure */
typedef struct cli_args {
    command_type_t command;
    int duration;                  /* Duration in seconds (0 = unlimited) */
    char *output_file;             /* Output file path (NULL = stdout) */
    output_format_t format;        /* Output format */
    int pid;                       /* Target PID (0 = all processes) */
    char *process_name;            /* Target process name (NULL = all) */
    char *library_filter;          /* Library name filter (NULL = all) */
    char *file_filter;             /* File path filter (NULL = all) */
    bool verbose;                  /* Verbose output */
    bool quiet;                    /* Quiet mode (minimal output) */
    bool no_redact;                /* Disable privacy redaction */
    bool follow_children;          /* Follow child processes */
    bool exit_after_parse;         /* Exit immediately after parsing (for help/version) */
} cli_args_t;

/* File type classification */
typedef enum {
    FILE_TYPE_CERTIFICATE = 0,
    FILE_TYPE_PRIVATE_KEY,
    FILE_TYPE_KEYSTORE,
    FILE_TYPE_UNKNOWN
} file_type_t;

/* Processed event structure for user-space processing */
typedef struct processed_event {
    char *event_type;          /* Event type string (file_open, lib_load, etc.) */
    char *timestamp;           /* ISO 8601 formatted timestamp */
    uint32_t pid;              /* Process ID */
    uint32_t uid;              /* User ID */
    char *process;             /* Process name */
    char *exe;                 /* Executable path (enriched from /proc) */
    char *cmdline;             /* Command line (for process_exec events) */
    
    /* Event-specific fields */
    char *file;                /* File path (for file_open events) */
    char *library;             /* Library path (for lib_load events) */
    char *library_name;        /* Extracted library name */
    char *function_name;       /* Function name (for api_call events) */
    int32_t exit_code;         /* Exit code (for process_exit events) */
    
    /* Classification and metadata */
    file_type_t file_type;     /* Classified file type */
    char *flags;               /* Human-readable flags (for file_open) */
    int32_t result;            /* System call result */
    
    /* Internal management */
    bool in_use;               /* Buffer pool management flag */
    struct processed_event *next; /* For free list */
} processed_event_t;

/* Event buffer pool for pre-allocated events */
typedef struct event_buffer_pool {
    processed_event_t *events;  /* Array of pre-allocated events */
    size_t capacity;            /* Total capacity (1000) */
    size_t in_use_count;        /* Number of events currently in use */
    processed_event_t *free_list; /* Linked list of free events */
} event_buffer_pool_t;

/* Profile structure for process profiling */
typedef struct {
    char *profile_version;
    char *generated_at;
    int duration_seconds;
    
    struct {
        uint32_t pid;
        char *name;
        char *exe;
        char *cmdline;
        uint32_t uid;
        uint32_t gid;
        char *start_time;
    } process;
    
    struct {
        char *name;
        char *path;
        char *load_time;
    } *libraries;
    size_t library_count;
    
    struct {
        char *path;
        char *type;
        int access_count;
        char *first_access;
        char *last_access;
        char *mode;
    } *files_accessed;
    size_t file_count;
    
    struct {
        char *function_name;
        int count;
    } *api_calls;
    size_t api_call_count;
    
    struct {
        int total_events;
        int libraries_loaded;
        int files_accessed;
        int api_calls_made;
    } statistics;
} profile_t;

/* Snapshot structure for system-wide inventory */
typedef struct {
    char *snapshot_version;
    char *generated_at;
    char *hostname;
    char *kernel;
    
    struct {
        uint32_t pid;
        char *name;
        char *exe;
        char **libraries;
        size_t library_count;
        char **open_crypto_files;
        size_t file_count;
        char *running_as;
    } *processes;
    size_t process_count;
    
    struct {
        int total_processes;
        int total_libraries;
        int total_files;
    } summary;
} snapshot_t;

/* Forward declarations */
struct ebpf_manager;
struct event_processor;
struct output_formatter;

/* Function prototypes - will be implemented in later tasks */
int parse_args(int argc, char **argv, cli_args_t *args);
void print_usage(const char *program_name);
void print_version(void);
void print_command_help(command_type_t cmd);
int validate_privileges(void);
int check_kernel_version(void);
int setup_signal_handlers(void);
bool is_shutdown_requested(void);

/* Event buffer pool functions */
event_buffer_pool_t *event_buffer_pool_create(size_t capacity);
processed_event_t *event_buffer_pool_acquire(event_buffer_pool_t *pool);
void event_buffer_pool_release(event_buffer_pool_t *pool, processed_event_t *event);
void event_buffer_pool_destroy(event_buffer_pool_t *pool);

#endif /* __CRYPTO_TRACER_H__ */