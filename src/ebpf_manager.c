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
#include "logger.h"
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

/* Libbpf logging callback - integrate with our logger */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    /* Remove trailing newline if present */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    
    switch (level) {
        case LIBBPF_WARN:
            log_warn("libbpf: %s", buffer);
            break;
        case LIBBPF_INFO:
            log_info("libbpf: %s", buffer);
            break;
        case LIBBPF_DEBUG:
            log_debug("libbpf: %s", buffer);
            break;
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
        log_error("Failed to allocate eBPF manager");
        return NULL;
    }
    
    /* Create event buffer pool (1000 pre-allocated events) */
    mgr->event_pool = event_buffer_pool_create(1000);
    if (!mgr->event_pool) {
        log_error("Failed to create event buffer pool");
        free(mgr);
        return NULL;
    }
    
    log_debug("eBPF manager created with event pool capacity: 1000");
    
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
        log_warn("Programs already loaded");
        return 0;
    }
    
    log_debug("Loading eBPF programs...");
    
    /* Load file_open_trace program */
    log_debug("Loading file_open_trace program...");
    mgr->file_open_skel = file_open_trace_bpf__open();
    if (!mgr->file_open_skel) {
        log_warn("Failed to open file_open_trace BPF skeleton");
    } else {
        err = file_open_trace_bpf__load(mgr->file_open_skel);
        if (err) {
            log_bpf_verifier_error("file_open_trace", err, "Check kernel logs for details");
            file_open_trace_bpf__destroy(mgr->file_open_skel);
            mgr->file_open_skel = NULL;
        } else {
            loaded_count++;
            log_debug("file_open_trace program loaded successfully");
        }
    }
    
    /* Load lib_load_trace program */
    log_debug("Loading lib_load_trace program...");
    mgr->lib_load_skel = lib_load_trace_bpf__open();
    if (!mgr->lib_load_skel) {
        log_warn("Failed to open lib_load_trace BPF skeleton");
    } else {
        err = lib_load_trace_bpf__load(mgr->lib_load_skel);
        if (err) {
            log_bpf_verifier_error("lib_load_trace", err, "Check kernel logs for details");
            lib_load_trace_bpf__destroy(mgr->lib_load_skel);
            mgr->lib_load_skel = NULL;
        } else {
            loaded_count++;
            log_debug("lib_load_trace program loaded successfully");
        }
    }
    
    /* Load process_exec_trace program */
    log_debug("Loading process_exec_trace program...");
    mgr->process_exec_skel = process_exec_trace_bpf__open();
    if (!mgr->process_exec_skel) {
        log_warn("Failed to open process_exec_trace BPF skeleton");
    } else {
        err = process_exec_trace_bpf__load(mgr->process_exec_skel);
        if (err) {
            log_bpf_verifier_error("process_exec_trace", err, "Check kernel logs for details");
            process_exec_trace_bpf__destroy(mgr->process_exec_skel);
            mgr->process_exec_skel = NULL;
        } else {
            loaded_count++;
            log_debug("process_exec_trace program loaded successfully");
        }
    }
    
    /* Load process_exit_trace program */
    log_debug("Loading process_exit_trace program...");
    mgr->process_exit_skel = process_exit_trace_bpf__open();
    if (!mgr->process_exit_skel) {
        log_warn("Failed to open process_exit_trace BPF skeleton");
    } else {
        err = process_exit_trace_bpf__load(mgr->process_exit_skel);
        if (err) {
            log_bpf_verifier_error("process_exit_trace", err, "Check kernel logs for details");
            process_exit_trace_bpf__destroy(mgr->process_exit_skel);
            mgr->process_exit_skel = NULL;
        } else {
            loaded_count++;
            log_debug("process_exit_trace program loaded successfully");
        }
    }
    
    /* Load openssl_api_trace program (optional) */
    log_debug("Loading openssl_api_trace program (optional)...");
    mgr->openssl_api_skel = openssl_api_trace_bpf__open();
    if (!mgr->openssl_api_skel) {
        log_info("OpenSSL API tracing not available (optional feature)");
    } else {
        err = openssl_api_trace_bpf__load(mgr->openssl_api_skel);
        if (err) {
            log_info("OpenSSL API tracing not loaded (optional feature, error: %d)", err);
            openssl_api_trace_bpf__destroy(mgr->openssl_api_skel);
            mgr->openssl_api_skel = NULL;
        } else {
            loaded_count++;
        }
    }
    
    /* Check if at least core programs loaded */
    if (loaded_count == 0) {
        log_error_with_suggestion("Failed to load any eBPF programs",
                                   "Check kernel version (requires 4.15+) and BPF support");
        return -1;
    }
    
    mgr->programs_loaded = true;
    log_info("Successfully loaded %d eBPF program(s)", loaded_count);
    
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
        log_error("Programs not loaded yet");
        return -1;
    }
    
    if (mgr->programs_attached) {
        log_warn("Programs already attached");
        return 0;
    }
    
    log_debug("Attaching eBPF programs...");
    
    /* Attach file_open_trace program */
    if (mgr->file_open_skel) {
        log_debug("Attaching file_open_trace...");
        err = file_open_trace_bpf__attach(mgr->file_open_skel);
        if (err) {
            log_warn("Failed to attach file_open_trace: %d", err);
        } else {
            attached_count++;
            log_debug("file_open_trace attached successfully");
        }
    }
    
    /* Attach lib_load_trace program */
    if (mgr->lib_load_skel) {
        log_debug("Attaching lib_load_trace...");
        err = lib_load_trace_bpf__attach(mgr->lib_load_skel);
        if (err) {
            log_warn("Failed to attach lib_load_trace: %d", err);
        } else {
            attached_count++;
            log_debug("lib_load_trace attached successfully");
        }
    }
    
    /* Attach process_exec_trace program */
    if (mgr->process_exec_skel) {
        log_debug("Attaching process_exec_trace...");
        err = process_exec_trace_bpf__attach(mgr->process_exec_skel);
        if (err) {
            log_warn("Failed to attach process_exec_trace: %d", err);
        } else {
            attached_count++;
            log_debug("process_exec_trace attached successfully");
        }
    }
    
    /* Attach process_exit_trace program */
    if (mgr->process_exit_skel) {
        log_debug("Attaching process_exit_trace...");
        err = process_exit_trace_bpf__attach(mgr->process_exit_skel);
        if (err) {
            log_warn("Failed to attach process_exit_trace: %d", err);
        } else {
            attached_count++;
            log_debug("process_exit_trace attached successfully");
        }
    }
    
    /* Attach openssl_api_trace program (optional) */
    if (mgr->openssl_api_skel) {
        log_debug("Attaching openssl_api_trace (optional)...");
        err = openssl_api_trace_bpf__attach(mgr->openssl_api_skel);
        if (err) {
            log_info("OpenSSL API tracing not attached (optional): %d", err);
        } else {
            attached_count++;
            log_debug("openssl_api_trace attached successfully");
        }
    }
    
    if (attached_count == 0) {
        log_error("Failed to attach any eBPF programs");
        return -1;
    }
    
    mgr->programs_attached = true;
    log_info("Successfully attached %d eBPF program(s)", attached_count);
    
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
            log_warn("Event processing backpressure detected (batch size: %d)",
                     batch_ctx->events_in_batch);
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
            log_warn("Unknown event type: %u", header->event_type);
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
        log_error("Failed to get ring buffer FD");
        return -1;
    }
    
    log_debug("Ring buffer FD: %d", ring_buffer_fd);
    
    /* Allocate batch context */
    mgr->batch_ctx = calloc(1, sizeof(*mgr->batch_ctx));
    if (!mgr->batch_ctx) {
        log_error("Failed to allocate batch context");
        return -1;
    }
    
    mgr->batch_ctx->mgr = mgr;
    mgr->batch_ctx->callback = callback;
    mgr->batch_ctx->user_ctx = ctx;
    mgr->batch_ctx->events_in_batch = 0;
    mgr->batch_ctx->max_batch_size = 500; /* Process up to 500 events per poll */
    
    /* Create ring buffer manager */
    mgr->rb = ring_buffer__new(ring_buffer_fd, handle_event, mgr->batch_ctx, NULL);
    if (!mgr->rb) {
        log_system_error("Failed to create ring buffer");
        free(mgr->batch_ctx);
        mgr->batch_ctx = NULL;
        return -1;
    }
    
    log_debug("Ring buffer created successfully");
    
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
        log_error("Error polling ring buffer: %d", err);
        return err;
    }
    
    /* Log dropped events if any */
    if (mgr->events_dropped > 0) {
        static uint64_t last_drop_count = 0;
        if (mgr->events_dropped != last_drop_count) {
            log_warn("%lu events dropped due to backpressure",
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
        log_warn("Cleanup timeout reached, some resources may not be freed");
    } else {
        log_debug("eBPF manager cleanup completed successfully");
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
