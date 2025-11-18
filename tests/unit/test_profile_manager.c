// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_profile_manager.c - Unit tests for profile manager
 * Tests profile creation, event aggregation, and finalization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../src/include/profile_manager.h"
#include "../../src/include/crypto_tracer.h"
#include "../../src/include/event_processor.h"

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test assertion macro */
#define ASSERT(condition, message) do { \
    tests_run++; \
    if (condition) { \
        tests_passed++; \
    } else { \
        tests_failed++; \
        fprintf(stderr, "  FAILED: %s\n", message); \
        return -1; \
    } \
} while(0)

/* Test function declarations */
static int test_profile_manager_create(void);
static int test_profile_manager_add_event(void);
static int test_profile_manager_library_aggregation(void);
static int test_profile_manager_file_aggregation(void);
static int test_profile_manager_api_call_aggregation(void);
static int test_profile_manager_get_profile(void);
static int test_profile_manager_finalize_profile(void);
static int test_profile_manager_multiple_processes(void);
static int test_profile_free(void);

/**
 * Test profile manager creation
 */
static int test_profile_manager_create(void) {
    printf("Running test: profile_manager_create\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should return non-NULL");
    
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test adding events to profile manager
 */
static int test_profile_manager_add_event(void) {
    printf("Running test: profile_manager_add_event\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Create a test event */
    processed_event_t event = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .exe = "/usr/bin/test",
        .library = "/usr/lib/libssl.so.1.1",
        .library_name = "libssl"
    };
    
    int result = profile_manager_add_event(mgr, &event);
    ASSERT(result == 0, "profile_manager_add_event should succeed");
    
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test library aggregation and deduplication
 */
static int test_profile_manager_library_aggregation(void) {
    printf("Running test: profile_manager_library_aggregation\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Add first library load event */
    processed_event_t event1 = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .library = "/usr/lib/libssl.so.1.1",
        .library_name = "libssl"
    };
    
    profile_manager_add_event(mgr, &event1);
    
    /* Add second library load event (different library) */
    processed_event_t event2 = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:01.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .library = "/usr/lib/libcrypto.so.1.1",
        .library_name = "libcrypto"
    };
    
    profile_manager_add_event(mgr, &event2);
    
    /* Add duplicate library load event (should be deduplicated) */
    processed_event_t event3 = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:02.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .library = "/usr/lib/libssl.so.1.1",
        .library_name = "libssl"
    };
    
    profile_manager_add_event(mgr, &event3);
    
    /* Get profile and verify */
    profile_t *profile = profile_manager_get_profile(mgr, 1234);
    ASSERT(profile != NULL, "profile_manager_get_profile should return profile");
    ASSERT(profile->library_count == 2, "Should have 2 unique libraries (deduplicated)");
    ASSERT(profile->statistics.libraries_loaded == 2, "Statistics should show 2 libraries loaded");
    
    profile_free(profile);
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test file access aggregation and counting
 */
static int test_profile_manager_file_aggregation(void) {
    printf("Running test: profile_manager_file_aggregation\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Add first file open event */
    processed_event_t event1 = {
        .event_type = "file_open",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .file = "/etc/ssl/cert.pem",
        .file_type = FILE_TYPE_CERTIFICATE,
        .flags = "O_RDONLY"
    };
    
    profile_manager_add_event(mgr, &event1);
    
    /* Add second file open event (same file - should increment count) */
    processed_event_t event2 = {
        .event_type = "file_open",
        .timestamp = "2025-01-01T00:00:01.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .file = "/etc/ssl/cert.pem",
        .file_type = FILE_TYPE_CERTIFICATE,
        .flags = "O_RDONLY"
    };
    
    profile_manager_add_event(mgr, &event2);
    
    /* Add third file open event (different file) */
    processed_event_t event3 = {
        .event_type = "file_open",
        .timestamp = "2025-01-01T00:00:02.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .file = "/etc/ssl/private.key",
        .file_type = FILE_TYPE_PRIVATE_KEY,
        .flags = "O_RDONLY"
    };
    
    profile_manager_add_event(mgr, &event3);
    
    /* Get profile and verify */
    profile_t *profile = profile_manager_get_profile(mgr, 1234);
    ASSERT(profile != NULL, "profile_manager_get_profile should return profile");
    ASSERT(profile->file_count == 2, "Should have 2 unique files");
    ASSERT(profile->statistics.files_accessed == 2, "Statistics should show 2 files accessed");
    
    /* Find the cert.pem file and verify access count */
    bool found_cert = false;
    for (size_t i = 0; i < profile->file_count; i++) {
        if (strcmp(profile->files_accessed[i].path, "/etc/ssl/cert.pem") == 0) {
            found_cert = true;
            ASSERT(profile->files_accessed[i].access_count == 2, 
                   "cert.pem should have access_count of 2");
            break;
        }
    }
    ASSERT(found_cert, "Should find cert.pem in profile");
    
    profile_free(profile);
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test API call aggregation and counting
 */
static int test_profile_manager_api_call_aggregation(void) {
    printf("Running test: profile_manager_api_call_aggregation\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Add first API call event */
    processed_event_t event1 = {
        .event_type = "api_call",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .function_name = "SSL_connect"
    };
    
    profile_manager_add_event(mgr, &event1);
    
    /* Add second API call event (same function - should increment count) */
    processed_event_t event2 = {
        .event_type = "api_call",
        .timestamp = "2025-01-01T00:00:01.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .function_name = "SSL_connect"
    };
    
    profile_manager_add_event(mgr, &event2);
    
    /* Add third API call event (different function) */
    processed_event_t event3 = {
        .event_type = "api_call",
        .timestamp = "2025-01-01T00:00:02.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .function_name = "SSL_accept"
    };
    
    profile_manager_add_event(mgr, &event3);
    
    /* Get profile and verify */
    profile_t *profile = profile_manager_get_profile(mgr, 1234);
    ASSERT(profile != NULL, "profile_manager_get_profile should return profile");
    ASSERT(profile->api_call_count == 2, "Should have 2 unique API calls");
    ASSERT(profile->statistics.api_calls_made == 2, "Statistics should show 2 API calls made");
    
    /* Find SSL_connect and verify count */
    bool found_connect = false;
    for (size_t i = 0; i < profile->api_call_count; i++) {
        if (strcmp(profile->api_calls[i].function_name, "SSL_connect") == 0) {
            found_connect = true;
            ASSERT(profile->api_calls[i].count == 2, 
                   "SSL_connect should have count of 2");
            break;
        }
    }
    ASSERT(found_connect, "Should find SSL_connect in profile");
    
    profile_free(profile);
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test getting a profile
 */
static int test_profile_manager_get_profile(void) {
    printf("Running test: profile_manager_get_profile\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Add event */
    processed_event_t event = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .exe = "/usr/bin/test",
        .cmdline = "test --arg",
        .library = "/usr/lib/libssl.so.1.1",
        .library_name = "libssl"
    };
    
    profile_manager_add_event(mgr, &event);
    
    /* Get profile */
    profile_t *profile = profile_manager_get_profile(mgr, 1234);
    ASSERT(profile != NULL, "profile_manager_get_profile should return profile");
    ASSERT(profile->process.pid == 1234, "Profile should have correct PID");
    ASSERT(strcmp(profile->process.name, "test_process") == 0, "Profile should have correct process name");
    ASSERT(strcmp(profile->process.exe, "/usr/bin/test") == 0, "Profile should have correct exe");
    ASSERT(strcmp(profile->process.cmdline, "test --arg") == 0, "Profile should have correct cmdline");
    ASSERT(profile->process.uid == 1000, "Profile should have correct UID");
    
    profile_free(profile);
    
    /* Try to get non-existent profile */
    profile_t *no_profile = profile_manager_get_profile(mgr, 9999);
    ASSERT(no_profile == NULL, "Should return NULL for non-existent PID");
    
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test finalizing a profile
 */
static int test_profile_manager_finalize_profile(void) {
    printf("Running test: profile_manager_finalize_profile\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Add event */
    processed_event_t event = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .library = "/usr/lib/libssl.so.1.1",
        .library_name = "libssl"
    };
    
    profile_manager_add_event(mgr, &event);
    
    /* Finalize profile */
    profile_t *profile = profile_manager_finalize_profile(mgr, 1234, 30);
    ASSERT(profile != NULL, "profile_manager_finalize_profile should return profile");
    ASSERT(profile->duration_seconds == 30, "Profile should have correct duration");
    ASSERT(profile->profile_version != NULL, "Profile should have version");
    ASSERT(profile->generated_at != NULL, "Profile should have generated_at timestamp");
    
    profile_free(profile);
    
    /* Try to get finalized profile again (should return NULL) */
    profile_t *no_profile = profile_manager_get_profile(mgr, 1234);
    ASSERT(no_profile == NULL, "Should return NULL for finalized profile");
    
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test tracking multiple processes
 */
static int test_profile_manager_multiple_processes(void) {
    printf("Running test: profile_manager_multiple_processes\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Add event for process 1234 */
    processed_event_t event1 = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "process1",
        .library = "/usr/lib/libssl.so.1.1",
        .library_name = "libssl"
    };
    
    profile_manager_add_event(mgr, &event1);
    
    /* Add event for process 5678 */
    processed_event_t event2 = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:01.000000Z",
        .pid = 5678,
        .uid = 1001,
        .process = "process2",
        .library = "/usr/lib/libcrypto.so.1.1",
        .library_name = "libcrypto"
    };
    
    profile_manager_add_event(mgr, &event2);
    
    /* Get both profiles */
    profile_t *profile1 = profile_manager_get_profile(mgr, 1234);
    ASSERT(profile1 != NULL, "Should get profile for PID 1234");
    ASSERT(profile1->process.pid == 1234, "Profile 1 should have correct PID");
    ASSERT(strcmp(profile1->process.name, "process1") == 0, "Profile 1 should have correct name");
    
    profile_t *profile2 = profile_manager_get_profile(mgr, 5678);
    ASSERT(profile2 != NULL, "Should get profile for PID 5678");
    ASSERT(profile2->process.pid == 5678, "Profile 2 should have correct PID");
    ASSERT(strcmp(profile2->process.name, "process2") == 0, "Profile 2 should have correct name");
    
    profile_free(profile1);
    profile_free(profile2);
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Test profile_free
 */
static int test_profile_free(void) {
    printf("Running test: profile_free\n");
    
    profile_manager_t *mgr = profile_manager_create();
    ASSERT(mgr != NULL, "profile_manager_create should succeed");
    
    /* Add various events */
    processed_event_t event1 = {
        .event_type = "lib_load",
        .timestamp = "2025-01-01T00:00:00.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .library = "/usr/lib/libssl.so.1.1",
        .library_name = "libssl"
    };
    
    processed_event_t event2 = {
        .event_type = "file_open",
        .timestamp = "2025-01-01T00:00:01.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .file = "/etc/ssl/cert.pem",
        .file_type = FILE_TYPE_CERTIFICATE,
        .flags = "O_RDONLY"
    };
    
    processed_event_t event3 = {
        .event_type = "api_call",
        .timestamp = "2025-01-01T00:00:02.000000Z",
        .pid = 1234,
        .uid = 1000,
        .process = "test_process",
        .function_name = "SSL_connect"
    };
    
    profile_manager_add_event(mgr, &event1);
    profile_manager_add_event(mgr, &event2);
    profile_manager_add_event(mgr, &event3);
    
    /* Get profile and free it */
    profile_t *profile = profile_manager_get_profile(mgr, 1234);
    ASSERT(profile != NULL, "Should get profile");
    
    /* Free should not crash */
    profile_free(profile);
    
    /* Free NULL should not crash */
    profile_free(NULL);
    
    profile_manager_destroy(mgr);
    
    printf("  PASSED\n");
    return 0;
}

/**
 * Main test runner
 */
int main(void) {
    printf("=== Profile Manager Unit Tests ===\n\n");
    
    /* Run all tests */
    test_profile_manager_create();
    test_profile_manager_add_event();
    test_profile_manager_library_aggregation();
    test_profile_manager_file_aggregation();
    test_profile_manager_api_call_aggregation();
    test_profile_manager_get_profile();
    test_profile_manager_finalize_profile();
    test_profile_manager_multiple_processes();
    test_profile_free();
    
    /* Print summary */
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    
    if (tests_failed == 0) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed\n");
        return 1;
    }
}
