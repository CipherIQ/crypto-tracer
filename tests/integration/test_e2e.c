// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_e2e.c - End-to-end integration tests
 * Tests complete workflows and command execution
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        printf("Running test: %s\n", name); \
    } while (0)

#define ASSERT_TRUE(condition, message) \
    do { \
        if (!(condition)) { \
            printf("  FAILED: %s\n", message); \
            tests_failed++; \
            return; \
        } \
    } while (0)

#define TEST_PASS() \
    do { \
        printf("  PASSED\n"); \
        tests_passed++; \
    } while (0)

/**
 * Helper: Execute command and capture output
 */
static int execute_command(const char *cmd, char *output, size_t output_size) {
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }
    
    size_t total = 0;
    while (total < output_size - 1 && fgets(output + total, output_size - total, fp) != NULL) {
        total = strlen(output);
    }
    
    int status = pclose(fp);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/**
 * Helper: Check if running as root
 */
static bool is_root(void) {
    return geteuid() == 0;
}

/**
 * Test: Binary exists and is executable
 */
void test_binary_exists(void) {
    TEST("binary_exists");
    
    struct stat st;
    ASSERT_TRUE(stat("./build/crypto-tracer", &st) == 0, 
                "Binary should exist at ./build/crypto-tracer");
    ASSERT_TRUE(st.st_mode & S_IXUSR, 
                "Binary should be executable");
    
    TEST_PASS();
}

/**
 * Test: Version command
 */
void test_version_command(void) {
    TEST("version_command");
    
    char output[4096] = {0};
    int ret = execute_command("./build/crypto-tracer --version", output, sizeof(output));
    
    ASSERT_TRUE(ret == 0, "Version command should succeed");
    ASSERT_TRUE(strstr(output, "crypto-tracer") != NULL, 
                "Version output should contain 'crypto-tracer'");
    ASSERT_TRUE(strstr(output, "1.0.0") != NULL, 
                "Version output should contain version number");
    
    TEST_PASS();
}

/**
 * Test: Help command
 */
void test_help_command(void) {
    TEST("help_command");
    
    char output[4096] = {0};
    int ret = execute_command("./build/crypto-tracer --help", output, sizeof(output));
    
    ASSERT_TRUE(ret == 0, "Help command should succeed");
    ASSERT_TRUE(strstr(output, "Usage:") != NULL, 
                "Help output should contain usage information");
    ASSERT_TRUE(strstr(output, "monitor") != NULL, 
                "Help output should mention monitor command");
    ASSERT_TRUE(strstr(output, "profile") != NULL, 
                "Help output should mention profile command");
    ASSERT_TRUE(strstr(output, "snapshot") != NULL, 
                "Help output should mention snapshot command");
    
    TEST_PASS();
}

/**
 * Test: Invalid command
 */
void test_invalid_command(void) {
    TEST("invalid_command");
    
    char output[4096] = {0};
    int ret = execute_command("./build/crypto-tracer invalid-command 2>&1", output, sizeof(output));
    
    ASSERT_TRUE(ret != 0, "Invalid command should fail");
    ASSERT_TRUE(strstr(output, "Unknown command") != NULL || 
                strstr(output, "Invalid") != NULL, 
                "Error message should indicate invalid command");
    
    TEST_PASS();
}

/**
 * Test: Snapshot command (should work without privileges)
 */
void test_snapshot_command(void) {
    TEST("snapshot_command");
    
    char output[8192] = {0};
    int ret = execute_command("./build/crypto-tracer snapshot 2>&1", output, sizeof(output));
    
    if (ret != 0) {
        printf("  DEBUG: Return code: %d\n", ret);
        printf("  DEBUG: Output: %s\n", output);
    }
    
    ASSERT_TRUE(ret == 0, "Snapshot command should succeed");
    ASSERT_TRUE(strstr(output, "snapshot_version") != NULL || 
                strstr(output, "processes") != NULL, 
                "Snapshot output should contain JSON data");
    
    TEST_PASS();
}

/**
 * Test: Monitor command privilege check
 */
void test_monitor_privilege_check(void) {
    TEST("monitor_privilege_check");
    
    if (is_root()) {
        printf("  SKIPPED: Running as root, cannot test privilege check\n");
        tests_passed++;
        return;
    }
    
    char output[4096] = {0};
    int ret = execute_command("./build/crypto-tracer monitor --duration 1 2>&1", output, sizeof(output));
    
    ASSERT_TRUE(ret == 3, "Monitor without privileges should exit with code 3");
    ASSERT_TRUE(strstr(output, "Insufficient privileges") != NULL || 
                strstr(output, "CAP_BPF") != NULL, 
                "Error message should mention privileges");
    
    TEST_PASS();
}

/**
 * Test: Profile command requires target
 */
void test_profile_requires_target(void) {
    TEST("profile_requires_target");
    
    char output[4096] = {0};
    int ret = execute_command("./build/crypto-tracer profile 2>&1", output, sizeof(output));
    
    ASSERT_TRUE(ret != 0, "Profile without target should fail");
    ASSERT_TRUE(strstr(output, "PID") != NULL || 
                strstr(output, "name") != NULL || 
                strstr(output, "target") != NULL, 
                "Error message should mention missing target");
    
    TEST_PASS();
}

/**
 * Test: Invalid duration
 */
void test_invalid_duration(void) {
    TEST("invalid_duration");
    
    char output[4096] = {0};
    int ret = execute_command("./build/crypto-tracer monitor --duration -10 2>&1", output, sizeof(output));
    
    ASSERT_TRUE(ret != 0, "Negative duration should fail");
    ASSERT_TRUE(strstr(output, "Invalid") != NULL || 
                strstr(output, "duration") != NULL, 
                "Error message should mention invalid duration");
    
    TEST_PASS();
}

/**
 * Test: Invalid PID
 */
void test_invalid_pid(void) {
    TEST("invalid_pid");
    
    char output[4096] = {0};
    int ret = execute_command("./build/crypto-tracer profile --pid -1 2>&1", output, sizeof(output));
    
    ASSERT_TRUE(ret != 0, "Negative PID should fail");
    ASSERT_TRUE(strstr(output, "Invalid") != NULL || 
                strstr(output, "PID") != NULL, 
                "Error message should mention invalid PID");
    
    TEST_PASS();
}

/**
 * Test: Output file creation
 */
void test_output_file_creation(void) {
    TEST("output_file_creation");
    
    const char *test_file = "/tmp/crypto-tracer-test-output.json";
    unlink(test_file);  /* Remove if exists */
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "./build/crypto-tracer snapshot --output %s 2>&1", test_file);
    
    char output[4096] = {0};
    int ret = execute_command(cmd, output, sizeof(output));
    
    ASSERT_TRUE(ret == 0, "Snapshot with output file should succeed");
    
    struct stat st;
    ASSERT_TRUE(stat(test_file, &st) == 0, "Output file should be created");
    ASSERT_TRUE(st.st_size > 0, "Output file should not be empty");
    
    unlink(test_file);
    
    TEST_PASS();
}

/**
 * Test: JSON output format
 */
void test_json_output_format(void) {
    TEST("json_output_format");
    
    char output[8192] = {0};
    int ret = execute_command("./build/crypto-tracer snapshot --quiet 2>&1", output, sizeof(output));
    
    ASSERT_TRUE(ret == 0, "Snapshot should succeed");
    ASSERT_TRUE(strstr(output, "{") != NULL, "Output should contain JSON opening brace");
    ASSERT_TRUE(strstr(output, "}") != NULL, "Output should contain JSON closing brace");
    ASSERT_TRUE(strstr(output, "\"") != NULL, "Output should contain JSON quotes");
    
    TEST_PASS();
}

/**
 * Main test runner
 */
int main(void) {
    printf("=== crypto-tracer End-to-End Integration Tests ===\n\n");
    
    /* Basic functionality tests */
    test_binary_exists();
    test_version_command();
    test_help_command();
    test_invalid_command();
    
    /* Command tests */
    test_snapshot_command();
    test_monitor_privilege_check();
    test_profile_requires_target();
    
    /* Validation tests */
    test_invalid_duration();
    test_invalid_pid();
    
    /* Output tests */
    test_output_file_creation();
    test_json_output_format();
    
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