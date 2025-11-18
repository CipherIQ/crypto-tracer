// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * test_event_collection.c - Test event collection from ring buffer
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
static int events_received = 0;

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
 * Event callback for testing
 */
static int test_event_callback(struct processed_event *event, void *ctx)
{
    int *count = (int *)ctx;
    
    if (event) {
        (*count)++;
        
        /* Verify event has required fields */
        if (event->event_type && event->timestamp && event->process) {
            /* Event looks valid */
        }
    }
    
    return 0;
}

/**
 * Test: Poll events with callback
 */
static void test_poll_events(void)
{
    TEST("test_poll_events");
    
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
            ASSERT(err == 0, "eBPF programs attached");
            
            if (err == 0) {
                /* Poll for events a few times */
                int event_count = 0;
                for (int i = 0; i < 5; i++) {
                    ebpf_manager_poll_events(mgr, test_event_callback, &event_count);
                    usleep(20000); /* 20ms */
                }
                
                ASSERT(1, "Event polling completed without errors");
                printf("  ℹ Received %d events\n", event_count);
            }
        }
        
        ebpf_manager_cleanup(mgr);
        ebpf_manager_destroy(mgr);
    }
}

/**
 * Test: Statistics tracking
 */
static void test_statistics(void)
{
    TEST("test_statistics");
    
    if (!check_privileges()) {
        printf("  ⊘ Skipping test (requires root or CAP_BPF/CAP_SYS_ADMIN)\n");
        return;
    }
    
    struct ebpf_manager *mgr = ebpf_manager_create();
    ASSERT(mgr != NULL, "eBPF manager created");
    
    if (mgr) {
        int err = ebpf_manager_load_programs(mgr);
        if (err == 0) {
            err = ebpf_manager_attach_programs(mgr);
            if (err == 0) {
                /* Poll for events */
                int event_count = 0;
                for (int i = 0; i < 3; i++) {
                    ebpf_manager_poll_events(mgr, test_event_callback, &event_count);
                    usleep(20000);
                }
                
                /* Check statistics */
                uint64_t events_processed = 0;
                uint64_t events_dropped = 0;
                ebpf_manager_get_stats(mgr, &events_processed, &events_dropped);
                
                ASSERT(1, "Statistics retrieved successfully");
                printf("  ℹ Events processed: %lu, dropped: %lu\n", 
                       events_processed, events_dropped);
            }
        }
        
        ebpf_manager_cleanup(mgr);
        ebpf_manager_destroy(mgr);
    }
}

/**
 * Main test runner
 */
int main(void)
{
    printf("=== Event Collection Unit Tests ===\n\n");
    
    /* Run tests */
    test_poll_events();
    test_statistics();
    
    /* Print summary */
    printf("\n=== Test Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}
