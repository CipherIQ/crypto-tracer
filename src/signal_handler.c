// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * signal_handler.c - Signal handling for graceful shutdown
 * Implements SIGINT and SIGTERM handlers with atomic flag
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "include/crypto_tracer.h"

/* Global shutdown flag - atomic for signal safety
 * Requirements: 12.4, 16.3, 16.4, 16.5 */
volatile sig_atomic_t shutdown_requested = 0;

/**
 * Signal handler for SIGINT and SIGTERM
 * Sets atomic flag for graceful shutdown
 * Requirements: 12.4, 16.3
 */
static void signal_handler(int sig) {
    (void)sig; /* Unused parameter */
    
    /* Set atomic flag - safe to do in signal handler */
    shutdown_requested = 1;
    
    /* Optional: Print message on first signal */
    static volatile sig_atomic_t first_signal = 1;
    if (first_signal) {
        first_signal = 0;
        /* Use write() instead of fprintf() for signal safety */
        const char *msg = "\nShutdown requested, cleaning up...\n";
        ssize_t ret = write(STDERR_FILENO, msg, strlen(msg));
        (void)ret; /* Suppress unused result warning */
    }
}

/**
 * Setup signal handlers for graceful shutdown
 * Registers handlers for SIGINT (Ctrl+C) and SIGTERM
 * Requirements: 12.4, 16.3
 * Returns EXIT_SUCCESS on success, EXIT_GENERAL_ERROR on failure
 */
int setup_signal_handlers(void) {
    struct sigaction sa;
    
    /* Initialize signal action structure */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    /* Register SIGINT handler (Ctrl+C) */
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        fprintf(stderr, "Error: Failed to register SIGINT handler: %s\n", strerror(errno));
        return EXIT_GENERAL_ERROR;
    }
    
    /* Register SIGTERM handler */
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        fprintf(stderr, "Error: Failed to register SIGTERM handler: %s\n", strerror(errno));
        return EXIT_GENERAL_ERROR;
    }
    
    return EXIT_SUCCESS;
}

/**
 * Check if shutdown has been requested
 * Returns true if shutdown signal received
 */
bool is_shutdown_requested(void) {
    return shutdown_requested != 0;
}
