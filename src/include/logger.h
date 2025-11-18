// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * logger.h - Structured logging and diagnostics system
 * Provides INFO, WARN, ERROR, and DEBUG level logging with helpful error messages
 */

#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <stdarg.h>
#include <stdbool.h>

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG = 0,  /* Detailed debug information */
    LOG_LEVEL_INFO,       /* Informational messages */
    LOG_LEVEL_WARN,       /* Warning messages */
    LOG_LEVEL_ERROR       /* Error messages */
} log_level_t;

/* Logger configuration */
typedef struct {
    log_level_t min_level;  /* Minimum level to log */
    bool quiet;             /* Suppress all non-error output */
    bool verbose;           /* Enable debug output */
    FILE *output;           /* Output stream (default: stderr) */
} logger_config_t;

/* Initialize the logger with configuration */
void logger_init(const logger_config_t *config);

/* Set log level dynamically */
void logger_set_level(log_level_t level);

/* Set quiet mode */
void logger_set_quiet(bool quiet);

/* Set verbose mode */
void logger_set_verbose(bool verbose);

/* Core logging functions */
void log_debug(const char *format, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char *format, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *format, ...) __attribute__((format(printf, 1, 2)));
void log_error(const char *format, ...) __attribute__((format(printf, 1, 2)));

/* Logging with suggestions for error resolution */
void log_error_with_suggestion(const char *error_msg, const char *suggestion);

/* BPF-specific logging */
void log_bpf_verifier_error(const char *program_name, int error_code, const char *verifier_log);

/* Helper for logging system errors with errno */
void log_system_error(const char *operation);

#endif /* __LOGGER_H__ */
