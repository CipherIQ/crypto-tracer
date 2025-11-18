/* lib_load_trace.bpf.c - eBPF program for tracing library loading
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
SEC("uprobe/dlopen")
int trace_dlopen(struct pt_regs *ctx) {
    return 0;
}