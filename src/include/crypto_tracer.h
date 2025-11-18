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

#endif /* __CRYPTO_TRACER_H__ */