// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * process_exec_trace.bpf.c - eBPF program for tracing process execution
 * Monitors sched_process_exec tracepoint for new process execution
 * NOTE: Simplified to avoid BPF verifier issues with complex cmdline reading
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

/* Tracepoint for sched_process_exec
 * This fires when a process successfully executes a new program
 * Cmdline reading simplified - user-space can read full cmdline from /proc if needed
 */
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(void *ctx) {
    struct ct_process_exec_event *event;
    struct task_struct *task, *parent;
    __u64 pid_tgid;
    __u32 pid, ppid = 0;
    
    /* Get PID */
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    /* Fill event header */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = pid;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_PROCESS_EXEC;
    
    /* Read process name (comm) - this is the most important part */
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    
    /* Get current task for PPID */
    task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        /* Read PPID from task structure */
        parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            ppid = BPF_CORE_READ(parent, tgid);
        }
    }
    
    /* Store PPID */
    event->ppid = ppid;
    
    /* Set cmdline to process name (comm) - user-space can read full cmdline from /proc if needed */
    __builtin_memcpy(event->cmdline, event->header.comm, sizeof(event->header.comm));
    event->cmdline[sizeof(event->header.comm)] = '\0';
    
    /* Submit event to ring buffer */
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}
