// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * openssl_api_trace.bpf.c - eBPF program for tracing OpenSSL API calls
 *
 * Uses BPF map to aggregate SSL context state across API calls:
 * - SSL_use_certificate_file -> updates cert_path in map
 * - SSL_set_fd -> updates socket_fd in map
 * - SSL_set_cipher_list -> updates cipher_list in map
 * - SSL_connect/SSL_accept (return) -> emits enriched event with all state
 *
 * This enables single-observation correlation without user-space stitching.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

/* BPF hash map for SSL context state tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);                    /* SSL* pointer */
    __type(value, struct ssl_ctx_state);
} ssl_ctx_map SEC(".maps");

/* Map to track SSL* pointer across uprobe/uretprobe for handshake functions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);     /* pid_tgid */
    __type(value, __u64);   /* SSL* pointer */
} ssl_handshake_map SEC(".maps");

/* Map to track SSL_CTX* across SSL_new() entry/return for state propagation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);     /* pid_tgid */
    __type(value, __u64);   /* SSL_CTX* pointer */
} ssl_new_ctx_map SEC(".maps");

/* Map to track client/server mode per SSL* for SSL_do_handshake detection */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);     /* SSL* pointer */
    __type(value, __u8);    /* 0=client (connect), 1=server (accept) */
} ssl_mode_map SEC(".maps");

/* Helper function to copy string literal */
static __always_inline void copy_string(char *dst, const char *src, int max_len) {
    int i;
    for (i = 0; i < max_len - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* Common function to handle simple API call events (informational only) */
static __always_inline int handle_api_call(const char *function_name) {
    struct ct_api_call_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = bpf_get_current_pid_tgid() >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_API_CALL;
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));
    copy_string(event->function_name, function_name, sizeof(event->function_name));
    copy_string(event->library, "libssl", sizeof(event->library));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ============================================================
 * Informational API Call Probes
 * ============================================================ */

SEC("uprobe/SSL_CTX_new")
int trace_ssl_ctx_new(struct pt_regs *ctx) {
    return handle_api_call("SSL_CTX_new");
}

/* ============================================================
 * SSL_new() State Propagation Probes
 * Copies state from SSL_CTX* to new SSL* object
 * ============================================================ */

/**
 * SSL_new(SSL_CTX *ctx) entry - save SSL_CTX* for uretprobe
 * This is critical for server-side TLS where state is set on SSL_CTX
 * (e.g., SSL_CTX_use_certificate_file) before SSL_new() creates SSL objects.
 */
SEC("uprobe/SSL_new")
int trace_ssl_new_entry(struct pt_regs *ctx) {
    __u64 ssl_ctx = (__u64)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_new_ctx_map, &pid_tgid, &ssl_ctx, BPF_ANY);
    return 0;
}

/**
 * SSL_new() return - propagate state from SSL_CTX* to new SSL*
 * Copies accumulated state (cert_path, cipher_list) from the parent
 * SSL_CTX to the newly created SSL object.
 */
SEC("uretprobe/SSL_new")
int trace_ssl_new_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ssl = (__u64)PT_REGS_RC(ctx);

    /* Get SSL_CTX* from entry probe */
    __u64 *ctx_ptr = bpf_map_lookup_elem(&ssl_new_ctx_map, &pid_tgid);
    if (!ctx_ptr || !ssl) {
        bpf_map_delete_elem(&ssl_new_ctx_map, &pid_tgid);
        return 0;
    }
    __u64 ssl_ctx = *ctx_ptr;
    bpf_map_delete_elem(&ssl_new_ctx_map, &pid_tgid);

    /* Copy state from SSL_CTX to new SSL object */
    struct ssl_ctx_state *ctx_state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl_ctx);
    if (ctx_state) {
        /* Propagate state to the new SSL object */
        bpf_map_update_elem(&ssl_ctx_map, &ssl, ctx_state, BPF_ANY);
    }
    return 0;
}

/* ============================================================
 * State Accumulation Probes (update BPF map, no event emission)
 * ============================================================ */

/**
 * SSL_use_certificate_file(SSL *ssl, const char *file, int type)
 * Updates cert_path in SSL context state map.
 */
SEC("uprobe/SSL_use_certificate_file")
int trace_ssl_use_cert_file(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    const char *file = (const char *)PT_REGS_PARM2(ctx);

    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl);
    if (state) {
        /* Update existing state */
        bpf_probe_read_user_str(state->cert_path, sizeof(state->cert_path), file);
        state->has_cert = 1;
    } else {
        /* Create new state */
        struct ssl_ctx_state new_state = {};
        bpf_probe_read_user_str(new_state.cert_path, sizeof(new_state.cert_path), file);
        new_state.has_cert = 1;
        new_state.socket_fd = -1;
        bpf_map_update_elem(&ssl_ctx_map, &ssl, &new_state, BPF_ANY);
    }
    return 0;
}

/**
 * SSL_CTX_use_certificate_file - same as above but for SSL_CTX*
 * Note: SSL inherits from SSL_CTX, so we track both with same key type.
 */
SEC("uprobe/SSL_CTX_use_certificate_file")
int trace_ssl_ctx_use_cert_file(struct pt_regs *ctx) {
    __u64 ssl_ctx = (__u64)PT_REGS_PARM1(ctx);
    const char *file = (const char *)PT_REGS_PARM2(ctx);

    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl_ctx);
    if (state) {
        bpf_probe_read_user_str(state->cert_path, sizeof(state->cert_path), file);
        state->has_cert = 1;
    } else {
        struct ssl_ctx_state new_state = {};
        bpf_probe_read_user_str(new_state.cert_path, sizeof(new_state.cert_path), file);
        new_state.has_cert = 1;
        new_state.socket_fd = -1;
        bpf_map_update_elem(&ssl_ctx_map, &ssl_ctx, &new_state, BPF_ANY);
    }
    return 0;
}

/**
 * SSL_use_certificate_chain_file(SSL *ssl, const char *file)
 * Used by many servers including openssl s_server.
 * Updates cert_path in SSL context state map.
 */
SEC("uprobe/SSL_use_certificate_chain_file")
int trace_ssl_use_cert_chain_file(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    const char *file = (const char *)PT_REGS_PARM2(ctx);

    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl);
    if (state) {
        bpf_probe_read_user_str(state->cert_path, sizeof(state->cert_path), file);
        state->has_cert = 1;
    } else {
        struct ssl_ctx_state new_state = {};
        bpf_probe_read_user_str(new_state.cert_path, sizeof(new_state.cert_path), file);
        new_state.has_cert = 1;
        new_state.socket_fd = -1;
        bpf_map_update_elem(&ssl_ctx_map, &ssl, &new_state, BPF_ANY);
    }
    return 0;
}

/**
 * SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
 * Used by many servers including openssl s_server.
 * Updates cert_path in SSL_CTX context state map.
 */
SEC("uprobe/SSL_CTX_use_certificate_chain_file")
int trace_ssl_ctx_use_cert_chain_file(struct pt_regs *ctx) {
    __u64 ssl_ctx = (__u64)PT_REGS_PARM1(ctx);
    const char *file = (const char *)PT_REGS_PARM2(ctx);

    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl_ctx);
    if (state) {
        bpf_probe_read_user_str(state->cert_path, sizeof(state->cert_path), file);
        state->has_cert = 1;
    } else {
        struct ssl_ctx_state new_state = {};
        bpf_probe_read_user_str(new_state.cert_path, sizeof(new_state.cert_path), file);
        new_state.has_cert = 1;
        new_state.socket_fd = -1;
        bpf_map_update_elem(&ssl_ctx_map, &ssl_ctx, &new_state, BPF_ANY);
    }
    return 0;
}

/**
 * SSL_set_fd(SSL *ssl, int fd)
 * Updates socket_fd in SSL context state map.
 */
SEC("uprobe/SSL_set_fd")
int trace_ssl_set_fd(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    int fd = (int)PT_REGS_PARM2(ctx);

    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl);
    if (state) {
        state->socket_fd = fd;
        state->has_fd = 1;
    } else {
        struct ssl_ctx_state new_state = {};
        new_state.socket_fd = fd;
        new_state.has_fd = 1;
        bpf_map_update_elem(&ssl_ctx_map, &ssl, &new_state, BPF_ANY);
    }
    return 0;
}

/**
 * SSL_set_cipher_list(SSL *ssl, const char *str)
 * Updates cipher_list in SSL context state map.
 */
SEC("uprobe/SSL_set_cipher_list")
int trace_ssl_set_cipher_list(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    const char *ciphers = (const char *)PT_REGS_PARM2(ctx);

    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl);
    if (state) {
        bpf_probe_read_user_str(state->cipher_list, sizeof(state->cipher_list), ciphers);
        state->has_ciphers = 1;
    } else {
        struct ssl_ctx_state new_state = {};
        bpf_probe_read_user_str(new_state.cipher_list, sizeof(new_state.cipher_list), ciphers);
        new_state.has_ciphers = 1;
        new_state.socket_fd = -1;
        bpf_map_update_elem(&ssl_ctx_map, &ssl, &new_state, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/SSL_CTX_set_cipher_list")
int trace_ssl_ctx_set_cipher_list(struct pt_regs *ctx) {
    __u64 ssl_ctx = (__u64)PT_REGS_PARM1(ctx);
    const char *ciphers = (const char *)PT_REGS_PARM2(ctx);

    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl_ctx);
    if (state) {
        bpf_probe_read_user_str(state->cipher_list, sizeof(state->cipher_list), ciphers);
        state->has_ciphers = 1;
    } else {
        struct ssl_ctx_state new_state = {};
        bpf_probe_read_user_str(new_state.cipher_list, sizeof(new_state.cipher_list), ciphers);
        new_state.has_ciphers = 1;
        new_state.socket_fd = -1;
        bpf_map_update_elem(&ssl_ctx_map, &ssl_ctx, &new_state, BPF_ANY);
    }
    return 0;
}

/* ============================================================
 * Socket Address Resolution Helper
 *
 * Resolves remote IP:port from a socket FD by traversing kernel
 * data structures: task->files->fdt->fd[n]->private_data->sk
 * Must be called in process context (uprobe/uretprobe) while
 * the socket FD is still open.
 * ============================================================ */

static __always_inline void resolve_socket_addr(
    struct ct_tls_handshake_event *event, __s32 socket_fd)
{
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fds;
    struct file *file;
    struct socket *sock;
    struct sock *sk;

    if (socket_fd < 0)
        return;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return;

    files = BPF_CORE_READ(task, files);
    if (!files)
        return;

    fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return;

    /* Bounds check: make sure fd index is within the table */
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((__u32)socket_fd >= max_fds)
        return;

    fds = BPF_CORE_READ(fdt, fd);
    if (!fds)
        return;

    bpf_probe_read_kernel(&file, sizeof(file), &fds[socket_fd]);
    if (!file)
        return;

    /* file->private_data points to struct socket for socket files */
    sock = BPF_CORE_READ(file, private_data);
    if (!sock)
        return;

    sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return;

    /* Read IPv4 remote address and port from sock_common */
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    if (daddr != 0) {
        event->remote_addr = daddr;
        event->remote_port = bpf_ntohs(dport);
        event->local_port = sport;
        event->has_remote = 1;
    }
}

/* ============================================================
 * Handshake Completion Probes (emit enriched event)
 * ============================================================ */

/**
 * SSL_connect entry - save SSL* for uretprobe
 */
SEC("uprobe/SSL_connect")
int trace_ssl_connect_entry(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_handshake_map, &pid_tgid, &ssl, BPF_ANY);
    return 0;
}

/**
 * SSL_connect return - emit enriched TLS handshake event
 */
SEC("uretprobe/SSL_connect")
int trace_ssl_connect_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int result = (int)PT_REGS_RC(ctx);

    /* Get SSL* from entry probe */
    __u64 *ssl_ptr = bpf_map_lookup_elem(&ssl_handshake_map, &pid_tgid);
    if (!ssl_ptr) {
        return 0;
    }
    __u64 ssl = *ssl_ptr;
    bpf_map_delete_elem(&ssl_handshake_map, &pid_tgid);

    /* Get accumulated state */
    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl);

    /* Emit enriched TLS handshake event */
    struct ct_tls_handshake_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = pid_tgid >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_TLS_HANDSHAKE;
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));

    event->ssl_ctx = ssl;
    event->result = result;
    event->is_client = 1;  /* SSL_connect = client */

    if (state) {
        event->has_cert = state->has_cert;
        event->has_fd = state->has_fd;
        event->has_ciphers = state->has_ciphers;

        if (state->has_cert) {
            __builtin_memcpy(event->cert_path, state->cert_path, sizeof(event->cert_path));
        }
        if (state->has_fd) {
            event->socket_fd = state->socket_fd;
            resolve_socket_addr(event, state->socket_fd);
        }
        if (state->has_ciphers) {
            __builtin_memcpy(event->cipher_list, state->cipher_list, sizeof(event->cipher_list));
        }

        /* Clean up state after handshake */
        bpf_map_delete_elem(&ssl_ctx_map, &ssl);
    } else {
        event->has_cert = 0;
        event->has_fd = 0;
        event->has_ciphers = 0;
        event->socket_fd = -1;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * SSL_accept entry - save SSL* for uretprobe
 */
SEC("uprobe/SSL_accept")
int trace_ssl_accept_entry(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_handshake_map, &pid_tgid, &ssl, BPF_ANY);
    return 0;
}

/**
 * SSL_accept return - emit enriched TLS handshake event
 */
SEC("uretprobe/SSL_accept")
int trace_ssl_accept_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int result = (int)PT_REGS_RC(ctx);

    /* Get SSL* from entry probe */
    __u64 *ssl_ptr = bpf_map_lookup_elem(&ssl_handshake_map, &pid_tgid);
    if (!ssl_ptr) {
        return 0;
    }
    __u64 ssl = *ssl_ptr;
    bpf_map_delete_elem(&ssl_handshake_map, &pid_tgid);

    /* Get accumulated state */
    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl);

    /* Emit enriched TLS handshake event */
    struct ct_tls_handshake_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = pid_tgid >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_TLS_HANDSHAKE;
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));

    event->ssl_ctx = ssl;
    event->result = result;
    event->is_client = 0;  /* SSL_accept = server */

    if (state) {
        event->has_cert = state->has_cert;
        event->has_fd = state->has_fd;
        event->has_ciphers = state->has_ciphers;

        if (state->has_cert) {
            __builtin_memcpy(event->cert_path, state->cert_path, sizeof(event->cert_path));
        }
        if (state->has_fd) {
            event->socket_fd = state->socket_fd;
            resolve_socket_addr(event, state->socket_fd);
        }
        if (state->has_ciphers) {
            __builtin_memcpy(event->cipher_list, state->cipher_list, sizeof(event->cipher_list));
        }

        /* Clean up state after handshake */
        bpf_map_delete_elem(&ssl_ctx_map, &ssl);
    } else {
        event->has_cert = 0;
        event->has_fd = 0;
        event->has_ciphers = 0;
        event->socket_fd = -1;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ============================================================
 * SSL Mode Tracking Probes
 *
 * Python's ssl module (and other high-level libraries) use
 * SSL_do_handshake() instead of SSL_accept()/SSL_connect().
 * To detect client vs server mode, we track calls to:
 * - SSL_set_connect_state() → client
 * - SSL_set_accept_state() → server
 * ============================================================ */

/**
 * SSL_set_connect_state(SSL *ssl) - mark as client mode
 * Called by Python ssl.SSLSocket.do_handshake() for client connections.
 */
SEC("uprobe/SSL_set_connect_state")
int trace_ssl_set_connect_state(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    __u8 mode = 0;  /* 0 = client */
    bpf_map_update_elem(&ssl_mode_map, &ssl, &mode, BPF_ANY);
    return 0;
}

/**
 * SSL_set_accept_state(SSL *ssl) - mark as server mode
 * Called by Python ssl.SSLSocket.do_handshake() for server connections.
 */
SEC("uprobe/SSL_set_accept_state")
int trace_ssl_set_accept_state(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    __u8 mode = 1;  /* 1 = server */
    bpf_map_update_elem(&ssl_mode_map, &ssl, &mode, BPF_ANY);
    return 0;
}

/* ============================================================
 * SSL_do_handshake Probes
 *
 * Generic handshake function used by:
 * - Python ssl module
 * - nginx (some code paths)
 * - Go crypto/tls (via cgo)
 * - Any library that wraps OpenSSL
 *
 * Unlike SSL_connect/SSL_accept which implicitly indicate mode,
 * SSL_do_handshake requires us to check ssl_mode_map.
 * ============================================================ */

/**
 * SSL_do_handshake(SSL *ssl) entry - save SSL* for uretprobe
 */
SEC("uprobe/SSL_do_handshake")
int trace_ssl_do_handshake_entry(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_handshake_map, &pid_tgid, &ssl, BPF_ANY);
    return 0;
}

/**
 * SSL_do_handshake return - emit enriched TLS handshake event
 * Uses ssl_mode_map to determine if this is client or server.
 */
SEC("uretprobe/SSL_do_handshake")
int trace_ssl_do_handshake_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int result = (int)PT_REGS_RC(ctx);

    /* Get SSL* from entry probe */
    __u64 *ssl_ptr = bpf_map_lookup_elem(&ssl_handshake_map, &pid_tgid);
    if (!ssl_ptr) {
        return 0;
    }
    __u64 ssl = *ssl_ptr;
    bpf_map_delete_elem(&ssl_handshake_map, &pid_tgid);

    /* Get client/server mode from mode map */
    __u8 *mode = bpf_map_lookup_elem(&ssl_mode_map, &ssl);
    __u8 is_server = mode ? *mode : 0;  /* Default to client if unknown */

    /* Get accumulated state */
    struct ssl_ctx_state *state = bpf_map_lookup_elem(&ssl_ctx_map, &ssl);

    /* Emit enriched TLS handshake event */
    struct ct_tls_handshake_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.pid = pid_tgid >> 32;
    event->header.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->header.event_type = CT_EVENT_TLS_HANDSHAKE;
    bpf_get_current_comm(&event->header.comm, sizeof(event->header.comm));

    event->ssl_ctx = ssl;
    event->result = result;
    event->is_client = is_server ? 0 : 1;  /* Invert: is_server=1 means is_client=0 */

    if (state) {
        event->has_cert = state->has_cert;
        event->has_fd = state->has_fd;
        event->has_ciphers = state->has_ciphers;

        if (state->has_cert) {
            __builtin_memcpy(event->cert_path, state->cert_path, sizeof(event->cert_path));
        }
        if (state->has_fd) {
            event->socket_fd = state->socket_fd;
            /* Resolve remote addr from kernel sock while FD is still open.
             * Must happen here — by the time userspace processes the event,
             * short-lived processes (openssl s_client) have already closed the FD. */
            resolve_socket_addr(event, state->socket_fd);
        }
        if (state->has_ciphers) {
            __builtin_memcpy(event->cipher_list, state->cipher_list, sizeof(event->cipher_list));
        }

        /* Clean up state unconditionally to prevent map leak.
         * Failed handshakes (result != 1) must also release entries,
         * otherwise the 10k-entry map fills up from ntopng etc. */
        bpf_map_delete_elem(&ssl_ctx_map, &ssl);
        bpf_map_delete_elem(&ssl_mode_map, &ssl);
    } else {
        event->has_cert = 0;
        event->has_fd = 0;
        event->has_ciphers = 0;
        event->socket_fd = -1;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* ============================================================
 * SSL Object Cleanup Probes
 *
 * Ensure BPF map entries are cleaned up when SSL/SSL_CTX objects
 * are freed, preventing map exhaustion from long-lived contexts.
 * ============================================================ */

/**
 * SSL_free(SSL *ssl) - clean up any leftover map entries for this SSL*
 * Catches cases where SSL objects are freed without a handshake completing.
 */
SEC("uprobe/SSL_free")
int trace_ssl_free(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&ssl_ctx_map, &ssl);
    bpf_map_delete_elem(&ssl_mode_map, &ssl);
    return 0;
}

/**
 * SSL_CTX_free(SSL_CTX *ctx) - clean up SSL_CTX entries from ssl_ctx_map
 * SSL_CTX entries are created by trace_ssl_ctx_use_cert_file etc. but
 * never cleaned up otherwise, since only SSL* entries get cleaned on handshake.
 */
SEC("uprobe/SSL_CTX_free")
int trace_ssl_ctx_free(struct pt_regs *ctx) {
    __u64 ssl_ctx = (__u64)PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&ssl_ctx_map, &ssl_ctx);
    return 0;
}
