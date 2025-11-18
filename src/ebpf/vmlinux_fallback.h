/* vmlinux_fallback.h - Fallback kernel headers for non-BTF kernels
 * Copyright (C) 2024
 * 
 * This file contains minimal kernel structure definitions for systems
 * without BTF support. It should be used as a fallback when vmlinux.h
 * cannot be generated from the running kernel.
 */

#ifndef __VMLINUX_FALLBACK_H__
#define __VMLINUX_FALLBACK_H__

#include <linux/types.h>

/* Basic kernel types */
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

/* Process task structure (minimal) */
struct task_struct {
    int pid;
    int tgid;
    char comm[16];
    /* Other fields omitted for fallback */
};

/* File structure (minimal) */
struct file {
    /* Minimal definition for fallback */
    void *f_path;
};

/* pt_regs structure for different architectures */
#ifdef __x86_64__
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};
#endif

/* Tracepoint structures (minimal definitions) */
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
    char __data[0];
};

struct trace_event_raw_sched_process_exec {
    struct trace_entry ent;
    u32 pid;
    u32 old_pid;
    char filename[16];
    char __data[0];
};

struct trace_event_raw_sched_process_exit {
    struct trace_entry ent;
    char comm[16];
    pid_t pid;
    int prio;
    char __data[0];
};

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

#endif /* __VMLINUX_FALLBACK_H__ */