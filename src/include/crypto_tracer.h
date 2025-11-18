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

/* Forward declarations */
struct cli_args;
struct ebpf_manager;
struct event_processor;
struct output_formatter;

/* Function prototypes - will be implemented in later tasks */
int parse_args(int argc, char **argv, struct cli_args *args);
int validate_privileges(void);
int check_kernel_version(void);
int setup_signal_handlers(void);

#endif /* __CRYPTO_TRACER_H__ */