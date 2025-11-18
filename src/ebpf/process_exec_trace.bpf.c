/* process_exec_trace.bpf.c - eBPF program for tracing process execution
 * Copyright (C) 2024
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

/* Placeholder - will be implemented in later tasks */
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    return 0;
}