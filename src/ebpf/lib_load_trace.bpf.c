// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * lib_load_trace.bpf.c - eBPF program for tracing library loading
 * Monitors dlopen() calls for crypto library loading
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

/* Uprobe for dlopen() function in libc
 * dlopen() signature: void *dlopen(const char *filename, int flags)
 * On x86_64: filename is in rdi (PT_REGS_PARM1)
 * NOTE: Filtering moved to user-space to avoid BPF verifier issues
 */
SEC("uprobe/dlopen")
int trace_dlopen(struct pt_regs *ctx) {
    struct ct_lib_load_event *event;
    const char *filename_ptr;
    int len;

    filename_ptr = (const char *)PT_REGS_PARM1(ctx);
    if (!filename_ptr) {
        return 0;
    }

    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    /* Read library path directly into event structure */
    len = bpf_probe_read_user_str(event->lib_path, sizeof(event->lib_path), filename_ptr);
    if (len <= 1) {
        /* Empty or error - discard */
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    /* Fill event header */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = bpf_get_current_pid_tgid() >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_LIB_LOAD;

    /* Read process name (comm) */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));

    /* Submit event - filtering will happen in user-space */
    bpf_ringbuf_submit(event, 0);

    return 0;
}