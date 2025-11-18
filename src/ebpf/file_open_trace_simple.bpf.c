// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * file_open_trace_simple.bpf.c - Simplified eBPF program for testing
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

/* Minimal kprobe - just submit an event */
SEC("kprobe/do_sys_openat2")
int trace_do_sys_openat2(struct pt_regs *ctx) {
    struct ct_file_open_event *event;
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    /* Fill minimal event data */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = bpf_get_current_pid_tgid() >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_FILE_OPEN;
    
    /* Read process name */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Set filename to empty */
    event->filename[0] = 't';
    event->filename[1] = 'e';
    event->filename[2] = 's';
    event->filename[3] = 't';
    event->filename[4] = '\0';
    
    event->flags = 0;
    event->result = 0;
    
    /* Submit event */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}
