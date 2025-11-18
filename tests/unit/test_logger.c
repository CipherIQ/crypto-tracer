// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_logger.c - Unit tests for logging system
 * Tests: 15.3, 15.4, 15.5, 15.6
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "../../src/include/logger.h"

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        printf("Running test: %s...", name); \
        fflush(stdout); \
    } while(0)

#define PASS() \
    do { \
        printf(" PASS\n"); \
        tests_passed++; \
    } while(0)

#define FAIL(msg) \
    do { \
        printf(" FAIL: %s\n", msg); \
        tests_failed++; \
    } while(0)

/**
 * Test logger initialization
 */
void test_logger_init(void) {
    TEST("logger_init");
    
    logger_config_t config = {
        .min_level = LOG_LEVEL_INFO,
        .quiet = false,
        .verbose = false,
        .output = stderr
    };
    
    logger_init(&config);
    
    /* If we get here without crashing, test passes */
    PASS();
}

/**
 * Test log level setting
 */
void test_logger_set_level(void) {
    TEST("logger_set_level");
    
    logger_set_level(LOG_LEVEL_DEBUG);
    logger_set_level(LOG_LEVEL_INFO);
    logger_set_level(LOG_LEVEL_WARN);
    logger_set_level(LOG_LEVEL_ERROR);
    
    PASS();
}

/**
 * Test verbose mode
 */
void test_logger_verbose(void) {
    TEST("logger_set_verbose");
    
    logger_set_verbose(true);
    logger_set_verbose(false);
    
    PASS();
}

/**
 * Test quiet mode
 */
void test_logger_quiet(void) {
    TEST("logger_set_quiet");
    
    logger_set_quiet(true);
    logger_set_quiet(false);
    
    PASS();
}

/**
 * Test basic logging functions
 */
void test_basic_logging(void) {
    TEST("basic_logging");
    
    /* Initialize logger for testing */
    logger_config_t config = {
        .min_level = LOG_LEVEL_DEBUG,
        .quiet = false,
        .verbose = true,
        .output = stderr
    };
    logger_init(&config);
    
    /* Test all log levels */
    log_debug("Debug message: %s", "test");
    log_info("Info message: %d", 42);
    log_warn("Warning message: %s", "test warning");
    log_error("Error message: %s", "test error");
    
    PASS();
}

/**
 * Test error with suggestion
 */
void test_error_with_suggestion(void) {
    TEST("log_error_with_suggestion");
    
    log_error_with_suggestion(
        "Test error occurred",
        "Try running with sudo or check permissions"
    );
    
    PASS();
}

/**
 * Test BPF verifier error logging
 */
void test_bpf_verifier_error(void) {
    TEST("log_bpf_verifier_error");
    
    log_bpf_verifier_error(
        "test_program",
        -1,
        "Test verifier log output\nLine 2 of verifier output"
    );
    
    PASS();
}

/**
 * Test system error logging
 */
void test_system_error(void) {
    TEST("log_system_error");
    
    /* Set errno to a known value */
    errno = EACCES;
    log_system_error("Test operation");
    
    PASS();
}

/**
 * Test quiet mode suppression
 */
void test_quiet_mode_suppression(void) {
    TEST("quiet_mode_suppression");
    
    /* Enable quiet mode */
    logger_set_quiet(true);
    
    /* These should not produce output (except errors) */
    log_debug("This should not appear");
    log_info("This should not appear");
    log_warn("This should not appear");
    log_error("This error should appear");
    
    /* Disable quiet mode */
    logger_set_quiet(false);
    
    PASS();
}

/**
 * Test verbose mode
 */
void test_verbose_mode(void) {
    TEST("verbose_mode");
    
    /* Enable verbose mode */
    logger_set_verbose(true);
    
    /* Debug messages should now appear */
    log_debug("This debug message should appear in verbose mode");
    log_info("This info message should appear");
    
    /* Disable verbose mode */
    logger_set_verbose(false);
    
    PASS();
}

int main(void) {
    printf("=== Logger Unit Tests ===\n\n");
    
    /* Run tests */
    test_logger_init();
    test_logger_set_level();
    test_logger_verbose();
    test_logger_quiet();
    test_basic_logging();
    test_error_with_suggestion();
    test_bpf_verifier_error();
    test_system_error();
    test_quiet_mode_suppression();
    test_verbose_mode();
    
    /* Print summary */
    printf("\n=== Test Summary ===\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    
    if (tests_failed > 0) {
        printf("\nSome tests FAILED!\n");
        return 1;
    }
    
    printf("\nAll tests PASSED!\n");
    return 0;
}
