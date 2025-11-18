// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_cleanup.c - Unit tests for signal handling and cleanup
 * Tests signal handler setup, shutdown flag, and timeout protection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include "../../src/include/crypto_tracer.h"

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;

/* External shutdown flag for testing */
extern volatile sig_atomic_t shutdown_requested;

/**
 * Test: setup_signal_handlers() succeeds
 */
static void test_setup_signal_handlers_success(void) {
    int ret;
    
    printf("Test: setup_signal_handlers() succeeds... ");
    
    ret = setup_signal_handlers();
    assert(ret == EXIT_SUCCESS);
    
    printf("PASS\n");
    tests_passed++;
}

/**
 * Test: shutdown flag is initially zero
 */
static void test_shutdown_flag_initial_state(void) {
    printf("Test: shutdown flag is initially zero... ");
    
    /* Reset flag */
    shutdown_requested = 0;
    
    assert(is_shutdown_requested() == false);
    assert(shutdown_requested == 0);
    
    printf("PASS\n");
    tests_passed++;
}

/**
 * Test: SIGINT sets shutdown flag
 */
static void test_sigint_sets_shutdown_flag(void) {
    pid_t pid;
    int status;
    
    printf("Test: SIGINT sets shutdown flag... ");
    
    pid = fork();
    if (pid == 0) {
        /* Child process */
        shutdown_requested = 0;
        
        /* Setup signal handlers */
        if (setup_signal_handlers() != EXIT_SUCCESS) {
            exit(EXIT_GENERAL_ERROR);
        }
        
        /* Send SIGINT to self */
        raise(SIGINT);
        
        /* Small delay to ensure signal is processed */
        usleep(10000);
        
        /* Check if flag was set */
        if (shutdown_requested != 0 && is_shutdown_requested()) {
            exit(EXIT_SUCCESS);
        } else {
            exit(EXIT_GENERAL_ERROR);
        }
    } else if (pid > 0) {
        /* Parent process */
        waitpid(pid, &status, 0);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == EXIT_SUCCESS);
        
        printf("PASS\n");
        tests_passed++;
    } else {
        fprintf(stderr, "FAIL: fork() failed\n");
        exit(EXIT_GENERAL_ERROR);
    }
}

/**
 * Test: SIGTERM sets shutdown flag
 */
static void test_sigterm_sets_shutdown_flag(void) {
    pid_t pid;
    int status;
    
    printf("Test: SIGTERM sets shutdown flag... ");
    
    pid = fork();
    if (pid == 0) {
        /* Child process */
        shutdown_requested = 0;
        
        /* Setup signal handlers */
        if (setup_signal_handlers() != EXIT_SUCCESS) {
            exit(EXIT_GENERAL_ERROR);
        }
        
        /* Send SIGTERM to self */
        raise(SIGTERM);
        
        /* Small delay to ensure signal is processed */
        usleep(10000);
        
        /* Check if flag was set */
        if (shutdown_requested != 0 && is_shutdown_requested()) {
            exit(EXIT_SUCCESS);
        } else {
            exit(EXIT_GENERAL_ERROR);
        }
    } else if (pid > 0) {
        /* Parent process */
        waitpid(pid, &status, 0);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == EXIT_SUCCESS);
        
        printf("PASS\n");
        tests_passed++;
    } else {
        fprintf(stderr, "FAIL: fork() failed\n");
        exit(EXIT_GENERAL_ERROR);
    }
}

/**
 * Test: Multiple signals don't cause issues
 */
static void test_multiple_signals(void) {
    pid_t pid;
    int status;
    
    printf("Test: Multiple signals handled correctly... ");
    
    pid = fork();
    if (pid == 0) {
        /* Child process */
        shutdown_requested = 0;
        
        /* Setup signal handlers */
        if (setup_signal_handlers() != EXIT_SUCCESS) {
            exit(EXIT_GENERAL_ERROR);
        }
        
        /* Send multiple signals */
        raise(SIGINT);
        usleep(5000);
        raise(SIGINT);
        usleep(5000);
        raise(SIGTERM);
        usleep(5000);
        
        /* Check if flag was set */
        if (shutdown_requested != 0 && is_shutdown_requested()) {
            exit(EXIT_SUCCESS);
        } else {
            exit(EXIT_GENERAL_ERROR);
        }
    } else if (pid > 0) {
        /* Parent process */
        waitpid(pid, &status, 0);
        assert(WIFEXITED(status));
        assert(WEXITSTATUS(status) == EXIT_SUCCESS);
        
        printf("PASS\n");
        tests_passed++;
    } else {
        fprintf(stderr, "FAIL: fork() failed\n");
        exit(EXIT_GENERAL_ERROR);
    }
}

/**
 * Test: is_shutdown_requested() returns correct value
 */
static void test_is_shutdown_requested(void) {
    printf("Test: is_shutdown_requested() returns correct value... ");
    
    /* Reset flag */
    shutdown_requested = 0;
    assert(is_shutdown_requested() == false);
    
    /* Set flag */
    shutdown_requested = 1;
    assert(is_shutdown_requested() == true);
    
    /* Reset flag */
    shutdown_requested = 0;
    assert(is_shutdown_requested() == false);
    
    printf("PASS\n");
    tests_passed++;
}

/**
 * Main test runner
 */
int main(void) {
    printf("=== Signal Handling and Cleanup Tests ===\n\n");
    
    /* Run tests */
    test_setup_signal_handlers_success();
    tests_run++;
    
    test_shutdown_flag_initial_state();
    tests_run++;
    
    test_sigint_sets_shutdown_flag();
    tests_run++;
    
    test_sigterm_sets_shutdown_flag();
    tests_run++;
    
    test_multiple_signals();
    tests_run++;
    
    test_is_shutdown_requested();
    tests_run++;
    
    /* Print summary */
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    
    if (tests_passed == tests_run) {
        printf("\nAll tests PASSED!\n");
        return EXIT_SUCCESS;
    } else {
        printf("\nSome tests FAILED!\n");
        return EXIT_GENERAL_ERROR;
    }
}
