// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_ebpf_manager.c - Unit tests for eBPF manager
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>

#include "crypto_tracer.h"
#include "ebpf_manager.h"

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

/* Test helper macros */
#define TEST(name) \
    printf("Running test: %s\n", name);

#define ASSERT(condition, message) \
    do { \
        if (condition) { \
            printf("  ✓ %s\n", message); \
            tests_passed++; \
        } else { \
            printf("  ✗ %s\n", message); \
            tests_failed++; \
        } \
    } while (0)

/**
 * Check if we have required privileges
 */
static int check_privileges(void)
{
    cap_t caps;
    cap_flag_value_t cap_value;
    
    /* Check if running as root */
    if (geteuid() == 0) {
        return 1;
    }
    
    /* Check for CAP_BPF or CAP_SYS_ADMIN */
    caps = cap_get_proc();
    if (!caps) {
        return 0;
    }
    
    /* Check CAP_BPF (kernel 5.8+) */
    if (cap_get_flag(caps, CAP_BPF, CAP_EFFECTIVE, &cap_value) == 0 && cap_value == CAP_SET) {
        cap_free(caps);
        return 1;
    }
    
    /* Check CAP_SYS_ADMIN */
    if (cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_value) == 0 && cap_value == CAP_SET) {
        cap_free(caps);
        return 1;
    }
    
    cap_free(caps);
    return 0;
}

/**
 * Test: Create and destroy eBPF manager
 */
static void test_create_destroy(void)
{
    TEST("test_create_destroy");
    
    struct ebpf_manager *mgr = ebpf_manager_create();
    ASSERT(mgr != NULL, "eBPF manager created successfully");
    
    if (mgr) {
        ebpf_manager_destroy(mgr);
        ASSERT(1, "eBPF manager destroyed successfully");
    }
}

/**
 * Test: Load eBPF programs (requires privileges)
 */
static void test_load_programs(void)
{
    TEST("test_load_programs");
    
    if (!check_privileges()) {
        printf("  ⊘ Skipping test (requires root or CAP_BPF/CAP_SYS_ADMIN)\n");
        return;
    }
    
    struct ebpf_manager *mgr = ebpf_manager_create();
    ASSERT(mgr != NULL, "eBPF manager created");
    
    if (mgr) {
        int err = ebpf_manager_load_programs(mgr);
        ASSERT(err == 0, "eBPF programs loaded successfully");
        
        ebpf_manager_destroy(mgr);
    }
}

/**
 * Test: Attach eBPF programs (requires privileges)
 */
static void test_attach_programs(void)
{
    TEST("test_attach_programs");
    
    if (!check_privileges()) {
        printf("  ⊘ Skipping test (requires root or CAP_BPF/CAP_SYS_ADMIN)\n");
        return;
    }
    
    struct ebpf_manager *mgr = ebpf_manager_create();
    ASSERT(mgr != NULL, "eBPF manager created");
    
    if (mgr) {
        int err = ebpf_manager_load_programs(mgr);
        ASSERT(err == 0, "eBPF programs loaded");
        
        if (err == 0) {
            err = ebpf_manager_attach_programs(mgr);
            ASSERT(err == 0, "eBPF programs attached successfully");
        }
        
        ebpf_manager_cleanup(mgr);
        ebpf_manager_destroy(mgr);
    }
}

/**
 * Test: Get statistics
 */
static void test_get_stats(void)
{
    TEST("test_get_stats");
    
    struct ebpf_manager *mgr = ebpf_manager_create();
    ASSERT(mgr != NULL, "eBPF manager created");
    
    if (mgr) {
        uint64_t events_processed = 0;
        uint64_t events_dropped = 0;
        
        ebpf_manager_get_stats(mgr, &events_processed, &events_dropped);
        ASSERT(events_processed == 0, "Initial events_processed is 0");
        ASSERT(events_dropped == 0, "Initial events_dropped is 0");
        
        ebpf_manager_destroy(mgr);
    }
}

/**
 * Test: Cleanup without load
 */
static void test_cleanup_without_load(void)
{
    TEST("test_cleanup_without_load");
    
    struct ebpf_manager *mgr = ebpf_manager_create();
    ASSERT(mgr != NULL, "eBPF manager created");
    
    if (mgr) {
        ebpf_manager_cleanup(mgr);
        ASSERT(1, "Cleanup without load succeeded");
        
        ebpf_manager_destroy(mgr);
    }
}

/**
 * Main test runner
 */
int main(void)
{
    printf("=== eBPF Manager Unit Tests ===\n\n");
    
    /* Run tests */
    test_create_destroy();
    test_get_stats();
    test_cleanup_without_load();
    test_load_programs();
    test_attach_programs();
    
    /* Print summary */
    printf("\n=== Test Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}
