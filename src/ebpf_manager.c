// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * ebpf_manager.c - eBPF program lifecycle management
 * Handles loading, attaching, event collection, and cleanup of eBPF programs
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "crypto_tracer.h"
#include "ebpf_manager.h"
#include "ebpf/common.h"

/* Include generated BPF skeletons */
#include "file_open_trace.skel.h"
#include "lib_load_trace.skel.h"
#include "process_exec_trace.skel.h"
#include "process_exit_trace.skel.h"
#include "openssl_api_trace.skel.h"

/* eBPF manager structure */
struct ebpf_manager {
    /* BPF skeletons */
    struct file_open_trace_bpf *file_open_skel;
    struct lib_load_trace_bpf *lib_load_skel;
    struct process_exec_trace_bpf *process_exec_skel;
    struct process_exit_trace_bpf *process_exit_skel;
    struct openssl_api_trace_bpf *openssl_api_skel;
    
    /* Ring buffer */
    struct ring_buffer *rb;
    struct event_batch_ctx *batch_ctx;
    
    /* Statistics */
    uint64_t events_processed;
    uint64_t events_dropped;
    
    /* Event buffer pool */
    event_buffer_pool_t *event_pool;
    
    /* Flags */
    bool programs_loaded;
    bool programs_attached;
};

/* Libbpf logging callback */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    /* Only print warnings and errors by default */
    if (level == LIBBPF_WARN || level == LIBBPF_INFO) {
        return vfprintf(stderr, format, args);
    }
    return 0;
}

/**
 * Create a new eBPF manager instance
 */
struct ebpf_manager *ebpf_manager_create(void)
{
    struct ebpf_manager *mgr;
    
    mgr = calloc(1, sizeof(*mgr));
    if (!mgr) {
        fprintf(stderr, "Error: Failed to allocate eBPF manager\n");
        return NULL;
    }
    
    /* Create event buffer pool (1000 pre-allocated events) */
    mgr->event_pool = event_buffer_pool_create(1000);
    if (!mgr->event_pool) {
        fprintf(stderr, "Error: Failed to create event buffer pool\n");
        free(mgr);
        return NULL;
    }
    
    /* Set up libbpf logging */
    libbpf_set_print(libbpf_print_fn);
    
    return mgr;
}

/**
 * Load all eBPF programs
 */
int ebpf_manager_load_programs(struct ebpf_manager *mgr)
{
    int err;
    int loaded_count = 0;
    
    if (!mgr) {
        return -EINVAL;
    }
    
    if (mgr->programs_loaded) {
        fprintf(stderr, "Warning: Programs already loaded\n");
        return 0;
    }
    
    /* Load file_open_trace program */
    mgr->file_open_skel = file_open_trace_bpf__open();
    if (!mgr->file_open_skel) {
        fprintf(stderr, "Warning: Failed to open file_open_trace BPF skeleton\n");
    } else {
        err = file_open_trace_bpf__load(mgr->file_open_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to load file_open_trace BPF program: %d\n", err);
            file_open_trace_bpf__destroy(mgr->file_open_skel);
            mgr->file_open_skel = NULL;
        } else {
            loaded_count++;
        }
    }
    
    /* Load lib_load_trace program */
    mgr->lib_load_skel = lib_load_trace_bpf__open();
    if (!mgr->lib_load_skel) {
        fprintf(stderr, "Warning: Failed to open lib_load_trace BPF skeleton\n");
    } else {
        err = lib_load_trace_bpf__load(mgr->lib_load_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to load lib_load_trace BPF program: %d\n", err);
            lib_load_trace_bpf__destroy(mgr->lib_load_skel);
            mgr->lib_load_skel = NULL;
        } else {
            loaded_count++;
        }
    }
    
    /* Load process_exec_trace program */
    mgr->process_exec_skel = process_exec_trace_bpf__open();
    if (!mgr->process_exec_skel) {
        fprintf(stderr, "Warning: Failed to open process_exec_trace BPF skeleton\n");
    } else {
        err = process_exec_trace_bpf__load(mgr->process_exec_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to load process_exec_trace BPF program: %d\n", err);
            process_exec_trace_bpf__destroy(mgr->process_exec_skel);
            mgr->process_exec_skel = NULL;
        } else {
            loaded_count++;
        }
    }
    
    /* Load process_exit_trace program */
    mgr->process_exit_skel = process_exit_trace_bpf__open();
    if (!mgr->process_exit_skel) {
        fprintf(stderr, "Warning: Failed to open process_exit_trace BPF skeleton\n");
    } else {
        err = process_exit_trace_bpf__load(mgr->process_exit_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to load process_exit_trace BPF program: %d\n", err);
            process_exit_trace_bpf__destroy(mgr->process_exit_skel);
            mgr->process_exit_skel = NULL;
        } else {
            loaded_count++;
        }
    }
    
    /* Load openssl_api_trace program (optional) */
    mgr->openssl_api_skel = openssl_api_trace_bpf__open();
    if (!mgr->openssl_api_skel) {
        fprintf(stderr, "Info: OpenSSL API tracing not available (optional feature)\n");
    } else {
        err = openssl_api_trace_bpf__load(mgr->openssl_api_skel);
        if (err) {
            fprintf(stderr, "Info: OpenSSL API tracing not loaded (optional feature): %d\n", err);
            openssl_api_trace_bpf__destroy(mgr->openssl_api_skel);
            mgr->openssl_api_skel = NULL;
        } else {
            loaded_count++;
        }
    }
    
    /* Check if at least core programs loaded */
    if (loaded_count == 0) {
        fprintf(stderr, "Error: Failed to load any eBPF programs\n");
        return -1;
    }
    
    mgr->programs_loaded = true;
    printf("Successfully loaded %d eBPF program(s)\n", loaded_count);
    
    return 0;
}

/**
 * Attach all loaded eBPF programs
 */
int ebpf_manager_attach_programs(struct ebpf_manager *mgr)
{
    int err;
    int attached_count = 0;
    
    if (!mgr) {
        return -EINVAL;
    }
    
    if (!mgr->programs_loaded) {
        fprintf(stderr, "Error: Programs not loaded yet\n");
        return -1;
    }
    
    if (mgr->programs_attached) {
        fprintf(stderr, "Warning: Programs already attached\n");
        return 0;
    }
    
    /* Attach file_open_trace program */
    if (mgr->file_open_skel) {
        err = file_open_trace_bpf__attach(mgr->file_open_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to attach file_open_trace: %d\n", err);
        } else {
            attached_count++;
        }
    }
    
    /* Attach lib_load_trace program */
    if (mgr->lib_load_skel) {
        err = lib_load_trace_bpf__attach(mgr->lib_load_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to attach lib_load_trace: %d\n", err);
        } else {
            attached_count++;
        }
    }
    
    /* Attach process_exec_trace program */
    if (mgr->process_exec_skel) {
        err = process_exec_trace_bpf__attach(mgr->process_exec_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to attach process_exec_trace: %d\n", err);
        } else {
            attached_count++;
        }
    }
    
    /* Attach process_exit_trace program */
    if (mgr->process_exit_skel) {
        err = process_exit_trace_bpf__attach(mgr->process_exit_skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to attach process_exit_trace: %d\n", err);
        } else {
            attached_count++;
        }
    }
    
    /* Attach openssl_api_trace program (optional) */
    if (mgr->openssl_api_skel) {
        err = openssl_api_trace_bpf__attach(mgr->openssl_api_skel);
        if (err) {
            fprintf(stderr, "Info: OpenSSL API tracing not attached (optional): %d\n", err);
        } else {
            attached_count++;
        }
    }
    
    if (attached_count == 0) {
        fprintf(stderr, "Error: Failed to attach any eBPF programs\n");
        return -1;
    }
    
    mgr->programs_attached = true;
    printf("Successfully attached %d eBPF program(s)\n", attached_count);
    
    return 0;
}

/* Event batch processing context */
struct event_batch_ctx {
    struct ebpf_manager *mgr;
    event_callback_t callback;
    void *user_ctx;
    int events_in_batch;
    int max_batch_size;
};

/**
 * Convert timestamp to ISO 8601 format
 */
static void format_timestamp(uint64_t timestamp_ns, char *buf, size_t buf_size)
{
    time_t sec = timestamp_ns / 1000000000ULL;
    uint64_t usec = (timestamp_ns % 1000000000ULL) / 1000;
    struct tm tm;
    
    gmtime_r(&sec, &tm);
    snprintf(buf, buf_size, "%04d-%02d-%02dT%02d:%02d:%02d.%06luZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, usec);
}

/**
 * Parse and process a file_open event
 */
static int process_file_open_event(struct ebpf_manager *mgr, struct ct_file_open_event *event,
                                   event_callback_t callback, void *ctx)
{
    processed_event_t *proc_event;
    char timestamp[64];
    int ret;
    
    /* Acquire event from buffer pool */
    proc_event = event_buffer_pool_acquire(mgr->event_pool);
    if (!proc_event) {
        mgr->events_dropped++;
        return -1;
    }
    
    /* Format timestamp */
    format_timestamp(event->header.timestamp_ns, timestamp, sizeof(timestamp));
    
    /* Fill processed event */
    proc_event->event_type = strdup("file_open");
    proc_event->timestamp = strdup(timestamp);
    proc_event->pid = event->header.pid;
    proc_event->uid = event->header.uid;
    proc_event->process = strndup(event->header.comm, MAX_COMM_LEN);
    proc_event->file = strndup(event->filename, MAX_FILENAME_LEN);
    proc_event->flags = NULL; /* Will be formatted later if needed */
    proc_event->result = event->result;
    
    /* Call user callback */
    ret = callback ? callback(proc_event, ctx) : 0;
    
    /* Release event back to pool */
    event_buffer_pool_release(mgr->event_pool, proc_event);
    
    return ret;
}

/**
 * Parse and process a lib_load event
 */
static int process_lib_load_event(struct ebpf_manager *mgr, struct ct_lib_load_event *event,
                                  event_callback_t callback, void *ctx)
{
    processed_event_t *proc_event;
    char timestamp[64];
    int ret;
    
    /* Acquire event from buffer pool */
    proc_event = event_buffer_pool_acquire(mgr->event_pool);
    if (!proc_event) {
        mgr->events_dropped++;
        return -1;
    }
    
    /* Format timestamp */
    format_timestamp(event->header.timestamp_ns, timestamp, sizeof(timestamp));
    
    /* Fill processed event */
    proc_event->event_type = strdup("lib_load");
    proc_event->timestamp = strdup(timestamp);
    proc_event->pid = event->header.pid;
    proc_event->uid = event->header.uid;
    proc_event->process = strndup(event->header.comm, MAX_COMM_LEN);
    proc_event->library = strndup(event->lib_path, MAX_LIBPATH_LEN);
    
    /* Call user callback */
    ret = callback ? callback(proc_event, ctx) : 0;
    
    /* Release event back to pool */
    event_buffer_pool_release(mgr->event_pool, proc_event);
    
    return ret;
}

/**
 * Parse and process a process_exec event
 */
static int process_exec_event(struct ebpf_manager *mgr, struct ct_process_exec_event *event,
                              event_callback_t callback, void *ctx)
{
    processed_event_t *proc_event;
    char timestamp[64];
    int ret;
    
    /* Acquire event from buffer pool */
    proc_event = event_buffer_pool_acquire(mgr->event_pool);
    if (!proc_event) {
        mgr->events_dropped++;
        return -1;
    }
    
    /* Format timestamp */
    format_timestamp(event->header.timestamp_ns, timestamp, sizeof(timestamp));
    
    /* Fill processed event */
    proc_event->event_type = strdup("process_exec");
    proc_event->timestamp = strdup(timestamp);
    proc_event->pid = event->header.pid;
    proc_event->uid = event->header.uid;
    proc_event->process = strndup(event->header.comm, MAX_COMM_LEN);
    proc_event->cmdline = strndup(event->cmdline, MAX_CMDLINE_LEN);
    
    /* Call user callback */
    ret = callback ? callback(proc_event, ctx) : 0;
    
    /* Release event back to pool */
    event_buffer_pool_release(mgr->event_pool, proc_event);
    
    return ret;
}

/**
 * Parse and process a process_exit event
 */
static int process_exit_event(struct ebpf_manager *mgr, struct ct_process_exit_event *event,
                              event_callback_t callback, void *ctx)
{
    processed_event_t *proc_event;
    char timestamp[64];
    int ret;
    
    /* Acquire event from buffer pool */
    proc_event = event_buffer_pool_acquire(mgr->event_pool);
    if (!proc_event) {
        mgr->events_dropped++;
        return -1;
    }
    
    /* Format timestamp */
    format_timestamp(event->header.timestamp_ns, timestamp, sizeof(timestamp));
    
    /* Fill processed event */
    proc_event->event_type = strdup("process_exit");
    proc_event->timestamp = strdup(timestamp);
    proc_event->pid = event->header.pid;
    proc_event->uid = event->header.uid;
    proc_event->process = strndup(event->header.comm, MAX_COMM_LEN);
    proc_event->exit_code = event->exit_code;
    
    /* Call user callback */
    ret = callback ? callback(proc_event, ctx) : 0;
    
    /* Release event back to pool */
    event_buffer_pool_release(mgr->event_pool, proc_event);
    
    return ret;
}

/**
 * Parse and process an api_call event
 */
static int process_api_call_event(struct ebpf_manager *mgr, struct ct_api_call_event *event,
                                  event_callback_t callback, void *ctx)
{
    processed_event_t *proc_event;
    char timestamp[64];
    int ret;
    
    /* Acquire event from buffer pool */
    proc_event = event_buffer_pool_acquire(mgr->event_pool);
    if (!proc_event) {
        mgr->events_dropped++;
        return -1;
    }
    
    /* Format timestamp */
    format_timestamp(event->header.timestamp_ns, timestamp, sizeof(timestamp));
    
    /* Fill processed event */
    proc_event->event_type = strdup("api_call");
    proc_event->timestamp = strdup(timestamp);
    proc_event->pid = event->header.pid;
    proc_event->uid = event->header.uid;
    proc_event->process = strndup(event->header.comm, MAX_COMM_LEN);
    proc_event->function_name = strndup(event->function_name, MAX_FUNCNAME_LEN);
    proc_event->library = strndup(event->library, MAX_FUNCNAME_LEN);
    
    /* Call user callback */
    ret = callback ? callback(proc_event, ctx) : 0;
    
    /* Release event back to pool */
    event_buffer_pool_release(mgr->event_pool, proc_event);
    
    return ret;
}

/**
 * Ring buffer callback handler
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event_batch_ctx *batch_ctx = ctx;
    struct ebpf_manager *mgr = batch_ctx->mgr;
    struct ct_event_header *header = data;
    int ret = 0;
    
    if (!mgr || !data || data_sz < sizeof(struct ct_event_header)) {
        return -1;
    }
    
    /* Update statistics */
    mgr->events_processed++;
    batch_ctx->events_in_batch++;
    
    /* Check batch size limit for backpressure */
    if (batch_ctx->events_in_batch >= batch_ctx->max_batch_size) {
        /* Log warning about backpressure */
        static uint64_t last_warning = 0;
        uint64_t now = header->timestamp_ns;
        if (now - last_warning > 1000000000ULL) { /* 1 second */
            fprintf(stderr, "Warning: Event processing backpressure detected\n");
            last_warning = now;
        }
    }
    
    /* Parse event based on type */
    switch (header->event_type) {
        case CT_EVENT_FILE_OPEN:
            if (data_sz >= sizeof(struct ct_file_open_event)) {
                ret = process_file_open_event(mgr, (struct ct_file_open_event *)data,
                                             batch_ctx->callback, batch_ctx->user_ctx);
            }
            break;
            
        case CT_EVENT_LIB_LOAD:
            if (data_sz >= sizeof(struct ct_lib_load_event)) {
                ret = process_lib_load_event(mgr, (struct ct_lib_load_event *)data,
                                            batch_ctx->callback, batch_ctx->user_ctx);
            }
            break;
            
        case CT_EVENT_PROCESS_EXEC:
            if (data_sz >= sizeof(struct ct_process_exec_event)) {
                ret = process_exec_event(mgr, (struct ct_process_exec_event *)data,
                                        batch_ctx->callback, batch_ctx->user_ctx);
            }
            break;
            
        case CT_EVENT_PROCESS_EXIT:
            if (data_sz >= sizeof(struct ct_process_exit_event)) {
                ret = process_exit_event(mgr, (struct ct_process_exit_event *)data,
                                        batch_ctx->callback, batch_ctx->user_ctx);
            }
            break;
            
        case CT_EVENT_API_CALL:
            if (data_sz >= sizeof(struct ct_api_call_event)) {
                ret = process_api_call_event(mgr, (struct ct_api_call_event *)data,
                                            batch_ctx->callback, batch_ctx->user_ctx);
            }
            break;
            
        default:
            fprintf(stderr, "Warning: Unknown event type: %u\n", header->event_type);
            break;
    }
    
    return ret;
}

/**
 * Setup ring buffer for event collection
 */
static int setup_ring_buffer(struct ebpf_manager *mgr, event_callback_t callback, void *ctx)
{
    int ring_buffer_fd = -1;
    
    if (!mgr) {
        return -EINVAL;
    }
    
    /* Get ring buffer FD from one of the loaded programs
     * All programs share the same ring buffer map */
    if (mgr->file_open_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->file_open_skel->maps.events);
    } else if (mgr->lib_load_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->lib_load_skel->maps.events);
    } else if (mgr->process_exec_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->process_exec_skel->maps.events);
    } else if (mgr->process_exit_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->process_exit_skel->maps.events);
    } else if (mgr->openssl_api_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->openssl_api_skel->maps.events);
    }
    
    if (ring_buffer_fd < 0) {
        fprintf(stderr, "Error: Failed to get ring buffer FD\n");
        return -1;
    }
    
    /* Allocate batch context */
    mgr->batch_ctx = calloc(1, sizeof(*mgr->batch_ctx));
    if (!mgr->batch_ctx) {
        fprintf(stderr, "Error: Failed to allocate batch context\n");
        return -1;
    }
    
    mgr->batch_ctx->mgr = mgr;
    mgr->batch_ctx->callback = callback;
    mgr->batch_ctx->user_ctx = ctx;
    mgr->batch_ctx->events_in_batch = 0;
    mgr->batch_ctx->max_batch_size = 100; /* Process up to 100 events per poll */
    
    /* Create ring buffer manager */
    mgr->rb = ring_buffer__new(ring_buffer_fd, handle_event, mgr->batch_ctx, NULL);
    if (!mgr->rb) {
        fprintf(stderr, "Error: Failed to create ring buffer: %s\n", strerror(errno));
        free(mgr->batch_ctx);
        mgr->batch_ctx = NULL;
        return -1;
    }
    
    return 0;
}

/**
 * Poll events from ring buffer with batching
 * Implements 10ms polling interval and processes up to 100 events per iteration
 */
int ebpf_manager_poll_events(struct ebpf_manager *mgr, event_callback_t callback, void *ctx)
{
    int err;
    
    if (!mgr) {
        return -EINVAL;
    }
    
    /* Setup ring buffer on first poll */
    if (!mgr->rb) {
        err = setup_ring_buffer(mgr, callback, ctx);
        if (err) {
            return err;
        }
    }
    
    /* Reset batch counter */
    if (mgr->batch_ctx) {
        mgr->batch_ctx->events_in_batch = 0;
    }
    
    /* Poll ring buffer with 10ms timeout
     * This will process up to max_batch_size events per call */
    err = ring_buffer__poll(mgr->rb, 10);
    if (err < 0 && err != -EINTR) {
        fprintf(stderr, "Error polling ring buffer: %d\n", err);
        return err;
    }
    
    /* Log dropped events if any */
    if (mgr->events_dropped > 0) {
        static uint64_t last_drop_count = 0;
        if (mgr->events_dropped != last_drop_count) {
            fprintf(stderr, "Warning: %lu events dropped due to backpressure\n",
                   mgr->events_dropped - last_drop_count);
            last_drop_count = mgr->events_dropped;
        }
    }
    
    return 0;
}

/**
 * Cleanup timeout handler
 */
static volatile sig_atomic_t cleanup_timeout = 0;

static void cleanup_alarm_handler(int sig)
{
    (void)sig;
    cleanup_timeout = 1;
}

/**
 * Cleanup and detach all eBPF programs with timeout protection
 * Implements proper detachment order: uprobes first, then tracepoints
 * Includes 5-second timeout protection for cleanup operations
 */
void ebpf_manager_cleanup(struct ebpf_manager *mgr)
{
    struct sigaction sa, old_sa;
    
    if (!mgr) {
        return;
    }
    
    /* Set up timeout protection (5 seconds) */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cleanup_alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGALRM, &sa, &old_sa) == 0) {
        alarm(5); /* 5-second timeout */
    }
    
    /* Detach and destroy programs in reverse order (uprobes first, then tracepoints) */
    
    /* Step 1: Detach uprobes first */
    if (mgr->openssl_api_skel && !cleanup_timeout) {
        openssl_api_trace_bpf__destroy(mgr->openssl_api_skel);
        mgr->openssl_api_skel = NULL;
    }
    
    if (mgr->lib_load_skel && !cleanup_timeout) {
        lib_load_trace_bpf__destroy(mgr->lib_load_skel);
        mgr->lib_load_skel = NULL;
    }
    
    /* Step 2: Detach tracepoints */
    if (mgr->process_exit_skel && !cleanup_timeout) {
        process_exit_trace_bpf__destroy(mgr->process_exit_skel);
        mgr->process_exit_skel = NULL;
    }
    
    if (mgr->process_exec_skel && !cleanup_timeout) {
        process_exec_trace_bpf__destroy(mgr->process_exec_skel);
        mgr->process_exec_skel = NULL;
    }
    
    if (mgr->file_open_skel && !cleanup_timeout) {
        file_open_trace_bpf__destroy(mgr->file_open_skel);
        mgr->file_open_skel = NULL;
    }
    
    /* Step 3: Cleanup ring buffer */
    if (mgr->rb && !cleanup_timeout) {
        ring_buffer__free(mgr->rb);
        mgr->rb = NULL;
    }
    
    /* Step 4: Free batch context */
    if (mgr->batch_ctx && !cleanup_timeout) {
        free(mgr->batch_ctx);
        mgr->batch_ctx = NULL;
    }
    
    /* Cancel alarm and restore old handler */
    alarm(0);
    sigaction(SIGALRM, &old_sa, NULL);
    
    if (cleanup_timeout) {
        fprintf(stderr, "Warning: Cleanup timeout reached, some resources may not be freed\n");
    }
    
    mgr->programs_loaded = false;
    mgr->programs_attached = false;
}

/**
 * Destroy eBPF manager and free resources
 */
void ebpf_manager_destroy(struct ebpf_manager *mgr)
{
    if (!mgr) {
        return;
    }
    
    /* Cleanup programs first */
    ebpf_manager_cleanup(mgr);
    
    /* Destroy event buffer pool */
    if (mgr->event_pool) {
        event_buffer_pool_destroy(mgr->event_pool);
        mgr->event_pool = NULL;
    }
    
    /* Free manager structure */
    free(mgr);
}

/**
 * Get statistics from eBPF manager
 */
void ebpf_manager_get_stats(struct ebpf_manager *mgr, uint64_t *events_processed, uint64_t *events_dropped)
{
    if (!mgr) {
        return;
    }
    
    if (events_processed) {
        *events_processed = mgr->events_processed;
    }
    
    if (events_dropped) {
        *events_dropped = mgr->events_dropped;
    }
}
