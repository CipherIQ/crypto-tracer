// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_proc_scanner.c - Unit tests for proc scanner
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "proc_scanner.h"

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        printf("Running test: %s\n", name); \
        tests_run++; \
    } while (0)

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("  FAILED: %s\n", message); \
            return; \
        } \
    } while (0)

#define TEST_PASS() \
    do { \
        printf("  PASSED\n"); \
        tests_passed++; \
    } while (0)

/**
 * Test: Create and destroy proc scanner
 */
void test_create_destroy(void) {
    TEST("test_create_destroy");
    
    proc_scanner_t *scanner = proc_scanner_create();
    ASSERT(scanner != NULL, "Failed to create proc scanner");
    
    proc_scanner_destroy(scanner);
    
    TEST_PASS();
}

/**
 * Test: Get process info for current process
 */
void test_get_process_info_self(void) {
    TEST("test_get_process_info_self");
    
    proc_scanner_t *scanner = proc_scanner_create();
    ASSERT(scanner != NULL, "Failed to create proc scanner");
    
    pid_t self_pid = getpid();
    process_info_t info;
    
    int ret = proc_scanner_get_process_info(scanner, self_pid, &info);
    ASSERT(ret == 0, "Failed to get process info for self");
    ASSERT(info.pid == self_pid, "PID mismatch");
    ASSERT(strlen(info.comm) > 0, "Process name is empty");
    ASSERT(strlen(info.exe) > 0, "Executable path is empty");
    
    proc_scanner_destroy(scanner);
    
    TEST_PASS();
}

/**
 * Test: Get process info for invalid PID
 */
void test_get_process_info_invalid(void) {
    TEST("test_get_process_info_invalid");
    
    proc_scanner_t *scanner = proc_scanner_create();
    ASSERT(scanner != NULL, "Failed to create proc scanner");
    
    process_info_t info;
    
    /* Use a very high PID that's unlikely to exist */
    int ret = proc_scanner_get_process_info(scanner, 999999, &info);
    ASSERT(ret != 0, "Should fail for invalid PID");
    
    proc_scanner_destroy(scanner);
    
    TEST_PASS();
}

/**
 * Test: Scan all processes
 */
void test_scan_processes(void) {
    TEST("test_scan_processes");
    
    proc_scanner_t *scanner = proc_scanner_create();
    ASSERT(scanner != NULL, "Failed to create proc scanner");
    
    process_list_t processes;
    process_list_init(&processes);
    
    int ret = proc_scanner_scan_processes(scanner, &processes);
    ASSERT(ret == 0, "Failed to scan processes");
    ASSERT(processes.count > 0, "No processes found");
    
    /* Verify we found at least our own process */
    pid_t self_pid = getpid();
    bool found_self = false;
    for (size_t i = 0; i < processes.count; i++) {
        if (processes.processes[i].pid == self_pid) {
            found_self = true;
            break;
        }
    }
    ASSERT(found_self, "Did not find self in process list");
    
    process_list_free(&processes);
    proc_scanner_destroy(scanner);
    
    TEST_PASS();
}

/**
 * Test: Get loaded libraries for current process
 */
void test_get_loaded_libraries(void) {
    TEST("test_get_loaded_libraries");
    
    proc_scanner_t *scanner = proc_scanner_create();
    ASSERT(scanner != NULL, "Failed to create proc scanner");
    
    pid_t self_pid = getpid();
    library_list_t libs;
    library_list_init(&libs);
    
    int ret = proc_scanner_get_loaded_libraries(scanner, self_pid, &libs);
    ASSERT(ret == 0, "Failed to get loaded libraries");
    
    /* We may or may not have crypto libraries loaded, so just check the call succeeded */
    /* If we do have crypto libraries, verify the structure is correct */
    for (size_t i = 0; i < libs.count; i++) {
        ASSERT(strlen(libs.libraries[i].path) > 0, "Library path is empty");
        ASSERT(strlen(libs.libraries[i].name) > 0, "Library name is empty");
    }
    
    library_list_free(&libs);
    proc_scanner_destroy(scanner);
    
    TEST_PASS();
}

/**
 * Test: Get open files for current process
 */
void test_get_open_files(void) {
    TEST("test_get_open_files");
    
    proc_scanner_t *scanner = proc_scanner_create();
    ASSERT(scanner != NULL, "Failed to create proc scanner");
    
    pid_t self_pid = getpid();
    file_list_t files;
    file_list_init(&files);
    
    int ret = proc_scanner_get_open_files(scanner, self_pid, &files);
    ASSERT(ret == 0, "Failed to get open files");
    
    /* We may or may not have crypto files open, so just check the call succeeded */
    /* If we do have crypto files, verify the structure is correct */
    for (size_t i = 0; i < files.count; i++) {
        ASSERT(strlen(files.files[i].path) > 0, "File path is empty");
        ASSERT(files.files[i].fd >= 0, "Invalid file descriptor");
    }
    
    file_list_free(&files);
    proc_scanner_destroy(scanner);
    
    TEST_PASS();
}

/**
 * Test: Process list operations
 */
void test_process_list_operations(void) {
    TEST("test_process_list_operations");
    
    process_list_t list;
    process_list_init(&list);
    
    ASSERT(list.count == 0, "Initial count should be 0");
    ASSERT(list.capacity == 0, "Initial capacity should be 0");
    
    /* Add some processes */
    for (int i = 0; i < 20; i++) {
        process_info_t info;
        memset(&info, 0, sizeof(info));
        info.pid = i + 1;
        snprintf(info.comm, sizeof(info.comm), "process%d", i);
        
        int ret = process_list_add(&list, &info);
        ASSERT(ret == 0, "Failed to add process to list");
    }
    
    ASSERT(list.count == 20, "Count should be 20");
    ASSERT(list.capacity >= 20, "Capacity should be at least 20");
    
    /* Verify contents */
    for (int i = 0; i < 20; i++) {
        ASSERT(list.processes[i].pid == i + 1, "PID mismatch");
    }
    
    process_list_free(&list);
    ASSERT(list.count == 0, "Count should be 0 after free");
    ASSERT(list.processes == NULL, "Processes should be NULL after free");
    
    TEST_PASS();
}

/**
 * Test: Library list operations
 */
void test_library_list_operations(void) {
    TEST("test_library_list_operations");
    
    library_list_t list;
    library_list_init(&list);
    
    ASSERT(list.count == 0, "Initial count should be 0");
    
    /* Add some libraries */
    for (int i = 0; i < 10; i++) {
        library_info_t info;
        snprintf(info.path, sizeof(info.path), "/usr/lib/libtest%d.so", i);
        snprintf(info.name, sizeof(info.name), "libtest%d", i);
        
        int ret = library_list_add(&list, &info);
        ASSERT(ret == 0, "Failed to add library to list");
    }
    
    ASSERT(list.count == 10, "Count should be 10");
    
    /* Try to add duplicate - should not increase count */
    library_info_t dup;
    strcpy(dup.path, "/usr/lib/libtest0.so");
    strcpy(dup.name, "libtest0");
    library_list_add(&list, &dup);
    ASSERT(list.count == 10, "Count should still be 10 after duplicate");
    
    library_list_free(&list);
    
    TEST_PASS();
}

/**
 * Test: File list operations
 */
void test_file_list_operations(void) {
    TEST("test_file_list_operations");
    
    file_list_t list;
    file_list_init(&list);
    
    ASSERT(list.count == 0, "Initial count should be 0");
    
    /* Add some files */
    for (int i = 0; i < 10; i++) {
        file_info_t info;
        snprintf(info.path, sizeof(info.path), "/etc/ssl/cert%d.pem", i);
        info.fd = i + 3;  /* Start from fd 3 */
        
        int ret = file_list_add(&list, &info);
        ASSERT(ret == 0, "Failed to add file to list");
    }
    
    ASSERT(list.count == 10, "Count should be 10");
    
    /* Try to add duplicate - should not increase count */
    file_info_t dup;
    strcpy(dup.path, "/etc/ssl/cert0.pem");
    dup.fd = 3;
    file_list_add(&list, &dup);
    ASSERT(list.count == 10, "Count should still be 10 after duplicate");
    
    file_list_free(&list);
    
    TEST_PASS();
}

/**
 * Test: Handle permission errors gracefully
 */
void test_permission_errors(void) {
    TEST("test_permission_errors");
    
    proc_scanner_t *scanner = proc_scanner_create();
    ASSERT(scanner != NULL, "Failed to create proc scanner");
    
    /* Try to get info for PID 1 (init) - may fail due to permissions */
    process_info_t info;
    int ret = proc_scanner_get_process_info(scanner, 1, &info);
    
    /* Should either succeed or fail gracefully (not crash) */
    if (ret == 0) {
        ASSERT(info.pid == 1, "PID should be 1");
        ASSERT(strlen(info.comm) > 0, "Process name should not be empty");
    }
    /* If it fails, that's also acceptable due to permissions */
    
    proc_scanner_destroy(scanner);
    
    TEST_PASS();
}

int main(void) {
    printf("Running proc_scanner unit tests...\n\n");
    
    test_create_destroy();
    test_get_process_info_self();
    test_get_process_info_invalid();
    test_scan_processes();
    test_get_loaded_libraries();
    test_get_open_files();
    test_process_list_operations();
    test_library_list_operations();
    test_file_list_operations();
    test_permission_errors();
    
    printf("\n========================================\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);
    printf("========================================\n");
    
    return (tests_run == tests_passed) ? 0 : 1;
}
