// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * common.h - Common definitions for eBPF programs
 * Shared event structures and constants between kernel and user space
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>

/* Maximum string lengths */
#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16
#define MAX_CMDLINE_LEN 256
#define MAX_LIBPATH_LEN 256
#define MAX_FUNCNAME_LEN 64

/* Event types */
enum event_type {
    EVENT_FILE_OPEN = 1,
    EVENT_LIB_LOAD = 2,
    EVENT_PROCESS_EXEC = 3,
    EVENT_PROCESS_EXIT = 4,
    EVENT_API_CALL = 5,
};

/* Base event header */
struct event_header {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    char comm[MAX_COMM_LEN];
    __u32 event_type;
};

/* File open event */
struct file_open_event {
    struct event_header header;
    char filename[MAX_FILENAME_LEN];
    __u32 flags;
    __s32 result;
};

/* Library load event */
struct lib_load_event {
    struct event_header header;
    char lib_path[MAX_LIBPATH_LEN];
};

/* Process execution event */
struct process_exec_event {
    struct event_header header;
    __u32 ppid;
    char cmdline[MAX_CMDLINE_LEN];
};

/* Process exit event */
struct process_exit_event {
    struct event_header header;
    __s32 exit_code;
};

/* API call event */
struct api_call_event {
    struct event_header header;
    char function_name[MAX_FUNCNAME_LEN];
    char library[MAX_FUNCNAME_LEN];
};

#endif /* __COMMON_H__ */