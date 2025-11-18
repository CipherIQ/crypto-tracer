// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * file_open_trace.bpf.c - eBPF program for tracing file open operations
 * Monitors sys_enter_open and sys_enter_openat for crypto file access
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

/* Common function to handle file open events
 * NOTE: Filtering moved to user-space to avoid BPF verifier issues
 * with complex string operations
 */
static __always_inline int handle_file_open(const char *filename_ptr, __u32 flags) {
    struct ct_file_open_event *event;
    int len;
    
    if (!filename_ptr) {
        return 0;
    }
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    /* Read filename directly into event structure */
    len = bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);
    if (len <= 1) {
        /* Empty or error - discard */
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    /* Fill event header */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = bpf_get_current_pid_tgid() >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_FILE_OPEN;
    
    /* Read process name (comm) */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Store flags */
    event->flags = flags;
    event->result = 0;
    
    /* Submit event - filtering will happen in user-space */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

/* Kprobe for do_sys_open (kernel function)
 * This is more reliable than tracepoints for file opening
 */
SEC("kprobe/do_sys_openat2")
int trace_do_sys_openat2(struct pt_regs *ctx) {
    const char *filename;
    __u32 flags = 0;
    
    /* do_sys_openat2(int dfd, const char __user *filename, struct open_how *how) */
    filename = (const char *)PT_REGS_PARM2(ctx);
    
    return handle_file_open(filename, flags);
}

/* Fallback kprobe for older kernels */
SEC("kprobe/do_sys_open")
int trace_do_sys_open(struct pt_regs *ctx) {
    const char *filename;
    __u32 flags;
    
    /* do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode) */
    filename = (const char *)PT_REGS_PARM2(ctx);
    flags = (__u32)PT_REGS_PARM3(ctx);
    
    return handle_file_open(filename, flags);
}