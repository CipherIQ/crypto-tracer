// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * logger.c - Structured logging and diagnostics system implementation
 * Requirements: 15.3, 15.4, 15.5, 15.6
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include "include/logger.h"

/* Global logger state */
static logger_config_t g_logger_config = {
    .min_level = LOG_LEVEL_INFO,
    .quiet = false,
    .verbose = false,
    .output = NULL  /* Will default to stderr */
};

/* Log level names for output */
static const char *log_level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

/* Log level colors (ANSI escape codes) */
static const char *log_level_colors[] = {
    "\033[36m",  /* DEBUG: Cyan */
    "\033[32m",  /* INFO: Green */
    "\033[33m",  /* WARN: Yellow */
    "\033[31m"   /* ERROR: Red */
};

static const char *color_reset = "\033[0m";

/**
 * Check if output is a TTY (for color support)
 */
static bool is_tty(FILE *stream) {
    if (!stream) {
        return false;
    }
    return isatty(fileno(stream));
}

/**
 * Initialize the logger with configuration
 * Requirement: 15.4 - Support --verbose and --quiet flags
 */
void logger_init(const logger_config_t *config) {
    if (config) {
        g_logger_config = *config;
    }
    
    /* Default to stderr if no output specified */
    if (!g_logger_config.output) {
        g_logger_config.output = stderr;
    }
    
    /* Apply verbose/quiet settings to log level */
    if (g_logger_config.verbose) {
        g_logger_config.min_level = LOG_LEVEL_DEBUG;
    } else if (g_logger_config.quiet) {
        g_logger_config.min_level = LOG_LEVEL_ERROR;
    }
}

/**
 * Set log level dynamically
 */
void logger_set_level(log_level_t level) {
    g_logger_config.min_level = level;
}

/**
 * Set quiet mode
 * Requirement: 15.4 - --quiet flag for minimal output
 */
void logger_set_quiet(bool quiet) {
    g_logger_config.quiet = quiet;
    if (quiet) {
        g_logger_config.min_level = LOG_LEVEL_ERROR;
    }
}

/**
 * Set verbose mode
 * Requirement: 15.4 - --verbose flag for debug output
 */
void logger_set_verbose(bool verbose) {
    g_logger_config.verbose = verbose;
    if (verbose) {
        g_logger_config.min_level = LOG_LEVEL_DEBUG;
    }
}

/**
 * Core logging function
 * Requirement: 15.3 - Structured logging with INFO, WARN, ERROR, DEBUG levels
 */
static void log_message(log_level_t level, const char *format, va_list args) {
    FILE *output;
    bool use_color;
    
    /* Check if we should log this level */
    if (level < g_logger_config.min_level) {
        return;
    }
    
    /* Quiet mode suppresses everything except errors */
    if (g_logger_config.quiet && level != LOG_LEVEL_ERROR) {
        return;
    }
    
    output = g_logger_config.output ? g_logger_config.output : stderr;
    use_color = is_tty(output);
    
    /* Print log level with optional color */
    if (use_color) {
        fprintf(output, "%s[%s]%s ", 
                log_level_colors[level],
                log_level_names[level],
                color_reset);
    } else {
        fprintf(output, "[%s] ", log_level_names[level]);
    }
    
    /* Print the actual message */
    vfprintf(output, format, args);
    fprintf(output, "\n");
    fflush(output);
}

/**
 * Debug level logging
 * Requirement: 15.3 - DEBUG level logging
 */
void log_debug(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_DEBUG, format, args);
    va_end(args);
}

/**
 * Info level logging
 * Requirement: 15.3 - INFO level logging
 */
void log_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_INFO, format, args);
    va_end(args);
}

/**
 * Warning level logging
 * Requirement: 15.3 - WARN level logging
 */
void log_warn(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_WARN, format, args);
    va_end(args);
}

/**
 * Error level logging
 * Requirement: 15.3 - ERROR level logging
 */
void log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_message(LOG_LEVEL_ERROR, format, args);
    va_end(args);
}

/**
 * Log error with helpful suggestion
 * Requirement: 15.5 - Create helpful error messages with suggested solutions
 */
void log_error_with_suggestion(const char *error_msg, const char *suggestion) {
    FILE *output = g_logger_config.output ? g_logger_config.output : stderr;
    bool use_color = is_tty(output);
    
    /* Print error message */
    if (use_color) {
        fprintf(output, "%s[ERROR]%s %s\n", 
                log_level_colors[LOG_LEVEL_ERROR],
                color_reset,
                error_msg);
    } else {
        fprintf(output, "[ERROR] %s\n", error_msg);
    }
    
    /* Print suggestion if provided */
    if (suggestion && strlen(suggestion) > 0) {
        if (use_color) {
            fprintf(output, "\033[1m→ Suggestion:\033[0m %s\n", suggestion);
        } else {
            fprintf(output, "→ Suggestion: %s\n", suggestion);
        }
    }
    
    fflush(output);
}

/**
 * Log BPF verifier errors with detailed information
 * Requirement: 15.6 - Add BPF verifier output logging for program load failures
 */
void log_bpf_verifier_error(const char *program_name, int error_code, const char *verifier_log) {
    FILE *output = g_logger_config.output ? g_logger_config.output : stderr;
    bool use_color = is_tty(output);
    
    /* Print error header */
    if (use_color) {
        fprintf(output, "%s[ERROR]%s Failed to load eBPF program: %s (error code: %d)\n",
                log_level_colors[LOG_LEVEL_ERROR],
                color_reset,
                program_name,
                error_code);
    } else {
        fprintf(output, "[ERROR] Failed to load eBPF program: %s (error code: %d)\n",
                program_name,
                error_code);
    }
    
    /* Print verifier log if available */
    if (verifier_log && strlen(verifier_log) > 0) {
        fprintf(output, "\nBPF Verifier Output:\n");
        fprintf(output, "----------------------------------------\n");
        fprintf(output, "%s", verifier_log);
        if (verifier_log[strlen(verifier_log) - 1] != '\n') {
            fprintf(output, "\n");
        }
        fprintf(output, "----------------------------------------\n");
    }
    
    /* Print helpful suggestions */
    fprintf(output, "\nPossible causes:\n");
    fprintf(output, "  1. Kernel version incompatibility (requires Linux 4.15+)\n");
    fprintf(output, "  2. Missing kernel features (CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y)\n");
    fprintf(output, "  3. BPF program complexity exceeds verifier limits\n");
    fprintf(output, "  4. Invalid memory access patterns in BPF code\n");
    fprintf(output, "\nTroubleshooting:\n");
    fprintf(output, "  - Check kernel version: uname -r\n");
    fprintf(output, "  - Verify BPF support: zgrep CONFIG_BPF /proc/config.gz\n");
    fprintf(output, "  - Run with --verbose for more details\n");
    fprintf(output, "  - Check dmesg for kernel messages: dmesg | tail -20\n");
    
    fflush(output);
}

/**
 * Log system errors with errno information
 * Requirement: 15.5 - Helpful error messages
 */
void log_system_error(const char *operation) {
    int saved_errno = errno;
    FILE *output = g_logger_config.output ? g_logger_config.output : stderr;
    bool use_color = is_tty(output);
    
    if (use_color) {
        fprintf(output, "%s[ERROR]%s %s: %s (errno: %d)\n",
                log_level_colors[LOG_LEVEL_ERROR],
                color_reset,
                operation,
                strerror(saved_errno),
                saved_errno);
    } else {
        fprintf(output, "[ERROR] %s: %s (errno: %d)\n",
                operation,
                strerror(saved_errno),
                saved_errno);
    }
    
    fflush(output);
}
