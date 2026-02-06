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
#include <limits.h>
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

    /* Manual uprobe links (auto-attach doesn't work for uprobes) */
    struct bpf_link *lib_load_link;           /* dlopen() in libc */
    struct bpf_link *ssl_ctx_new_link;        /* SSL_CTX_new() in libssl */
    struct bpf_link *ssl_new_entry_link;      /* SSL_new() entry */
    struct bpf_link *ssl_new_return_link;     /* SSL_new() return */
    struct bpf_link *ssl_connect_entry_link;  /* SSL_connect() entry */
    struct bpf_link *ssl_connect_return_link; /* SSL_connect() return */
    struct bpf_link *ssl_accept_entry_link;   /* SSL_accept() entry */
    struct bpf_link *ssl_accept_return_link;  /* SSL_accept() return */

    /* State accumulation uprobe links (update BPF map, no events emitted) */
    struct bpf_link *ssl_use_cert_file_link;      /* SSL_use_certificate_file() */
    struct bpf_link *ssl_ctx_use_cert_file_link;  /* SSL_CTX_use_certificate_file() */
    struct bpf_link *ssl_use_cert_chain_file_link;     /* SSL_use_certificate_chain_file() */
    struct bpf_link *ssl_ctx_use_cert_chain_file_link; /* SSL_CTX_use_certificate_chain_file() */
    struct bpf_link *ssl_set_fd_link;             /* SSL_set_fd() */
    struct bpf_link *ssl_set_cipher_list_link;    /* SSL_set_cipher_list() */
    struct bpf_link *ssl_ctx_set_cipher_list_link; /* SSL_CTX_set_cipher_list() */

    /* SSL_do_handshake probes for Python ssl module and other high-level libs */
    struct bpf_link *ssl_set_connect_state_link;  /* SSL_set_connect_state() - client mode */
    struct bpf_link *ssl_set_accept_state_link;   /* SSL_set_accept_state() - server mode */
    struct bpf_link *ssl_do_handshake_entry_link; /* SSL_do_handshake() entry */
    struct bpf_link *ssl_do_handshake_return_link;/* SSL_do_handshake() return */

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

/**
 * Find the full path to a shared library.
 * Searches /proc/self/maps first, then falls back to well-known paths.
 * Returns 0 on success, -1 on failure.
 */
static int find_library_path(const char *lib_name, char *path_out, size_t path_size)
{
    FILE *fp;
    char line[512];

    /* Method 1: Check /proc/self/maps (works if library is loaded in current process) */
    fp = fopen("/proc/self/maps", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, lib_name)) {
                /* Extract path from line (format: "addr-addr perms offset dev inode path") */
                char *path = strrchr(line, ' ');
                if (path && path[1] != '[') {
                    path++;  /* Skip space */
                    size_t len = strlen(path);
                    if (len > 0 && path[len - 1] == '\n') {
                        path[len - 1] = '\0';
                    }
                    strncpy(path_out, path, path_size - 1);
                    path_out[path_size - 1] = '\0';
                    fclose(fp);
                    return 0;
                }
            }
        }
        fclose(fp);
    }

    /* Method 2: Check well-known paths for common libraries */
    if (strstr(lib_name, "libc")) {
        const char *libc_paths[] = {
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib/libc.so.6",
            "/lib/libc.so.6",
            NULL
        };
        for (int i = 0; libc_paths[i]; i++) {
            if (access(libc_paths[i], F_OK) == 0) {
                strncpy(path_out, libc_paths[i], path_size - 1);
                path_out[path_size - 1] = '\0';
                return 0;
            }
        }
    } else if (strstr(lib_name, "libssl")) {
        const char *ssl_paths[] = {
            "/lib/x86_64-linux-gnu/libssl.so.3",
            "/lib/x86_64-linux-gnu/libssl.so.1.1",
            "/lib64/libssl.so.3",
            "/lib64/libssl.so.1.1",
            "/usr/lib/libssl.so.3",
            "/usr/lib/libssl.so.1.1",
            NULL
        };
        for (int i = 0; ssl_paths[i]; i++) {
            if (access(ssl_paths[i], F_OK) == 0) {
                strncpy(path_out, ssl_paths[i], path_size - 1);
                path_out[path_size - 1] = '\0';
                return 0;
            }
        }
    }

    return -1;
}

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
    
    /* Attach lib_load_trace program - manual uprobe attachment to dlopen() */
    if (mgr->lib_load_skel) {
        char libc_path[PATH_MAX];
        if (find_library_path("libc", libc_path, sizeof(libc_path)) == 0) {
            log_debug("Attaching lib_load_trace to %s:dlopen...", libc_path);
            LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
            uprobe_opts.func_name = "dlopen";
            uprobe_opts.retprobe = false;

            mgr->lib_load_link = bpf_program__attach_uprobe_opts(
                mgr->lib_load_skel->progs.trace_dlopen,
                -1,         /* Attach to all processes */
                libc_path,
                0,          /* Offset resolved from func_name */
                &uprobe_opts
            );

            if (!mgr->lib_load_link || libbpf_get_error(mgr->lib_load_link)) {
                log_warn("Failed to attach lib_load_trace: %s",
                         strerror(errno));
                mgr->lib_load_link = NULL;
            } else {
                attached_count++;
                log_info("lib_load_trace attached to %s:dlopen", libc_path);
            }
        } else {
            log_warn("Could not find libc.so path for lib_load_trace");
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
    
    /* Attach openssl_api_trace program (optional) - manual uprobe attachment */
    if (mgr->openssl_api_skel) {
        char libssl_path[PATH_MAX];
        if (find_library_path("libssl", libssl_path, sizeof(libssl_path)) == 0) {
            log_debug("Attaching openssl_api_trace to %s...", libssl_path);
            int ssl_attached = 0;

            /* Attach SSL_CTX_new uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_CTX_new";
                opts.retprobe = false;
                mgr->ssl_ctx_new_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_ctx_new,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_ctx_new_link && !libbpf_get_error(mgr->ssl_ctx_new_link)) {
                    ssl_attached++;
                } else {
                    mgr->ssl_ctx_new_link = NULL;
                }
            }

            /* Attach SSL_new entry uprobe (for SSL_CTX→SSL state propagation) */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_new";
                opts.retprobe = false;
                mgr->ssl_new_entry_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_new_entry,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_new_entry_link && !libbpf_get_error(mgr->ssl_new_entry_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_new entry uprobe");
                } else {
                    mgr->ssl_new_entry_link = NULL;
                }
            }

            /* Attach SSL_new return uretprobe (propagates state from SSL_CTX to SSL) */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_new";
                opts.retprobe = true;
                mgr->ssl_new_return_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_new_return,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_new_return_link && !libbpf_get_error(mgr->ssl_new_return_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_new return uretprobe");
                } else {
                    mgr->ssl_new_return_link = NULL;
                }
            }

            /* Attach SSL_connect entry uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_connect";
                opts.retprobe = false;
                mgr->ssl_connect_entry_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_connect_entry,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_connect_entry_link && !libbpf_get_error(mgr->ssl_connect_entry_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_connect entry uprobe");
                } else {
                    log_warn("Failed to attach SSL_connect entry uprobe: %ld",
                             libbpf_get_error(mgr->ssl_connect_entry_link));
                    mgr->ssl_connect_entry_link = NULL;
                }
            }

            /* Attach SSL_connect return uretprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_connect";
                opts.retprobe = true;
                mgr->ssl_connect_return_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_connect_return,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_connect_return_link && !libbpf_get_error(mgr->ssl_connect_return_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_connect return uretprobe");
                } else {
                    log_warn("Failed to attach SSL_connect return uretprobe: %ld",
                             libbpf_get_error(mgr->ssl_connect_return_link));
                    mgr->ssl_connect_return_link = NULL;
                }
            }

            /* Attach SSL_accept entry uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_accept";
                opts.retprobe = false;
                mgr->ssl_accept_entry_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_accept_entry,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_accept_entry_link && !libbpf_get_error(mgr->ssl_accept_entry_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_accept entry uprobe");
                } else {
                    log_warn("Failed to attach SSL_accept entry uprobe: %ld",
                             libbpf_get_error(mgr->ssl_accept_entry_link));
                    mgr->ssl_accept_entry_link = NULL;
                }
            }

            /* Attach SSL_accept return uretprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_accept";
                opts.retprobe = true;
                mgr->ssl_accept_return_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_accept_return,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_accept_return_link && !libbpf_get_error(mgr->ssl_accept_return_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_accept return uretprobe");
                } else {
                    log_warn("Failed to attach SSL_accept return uretprobe: %ld",
                             libbpf_get_error(mgr->ssl_accept_return_link));
                    mgr->ssl_accept_return_link = NULL;
                }
            }

            /* ============================================================
             * Phase 1-3 Enhancement Uprobes
             * ============================================================ */

            /* Phase 1: Attach SSL_use_certificate_file uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_use_certificate_file";
                opts.retprobe = false;
                mgr->ssl_use_cert_file_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_use_cert_file,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_use_cert_file_link &&
                    !libbpf_get_error(mgr->ssl_use_cert_file_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_use_certificate_file uprobe");
                } else {
                    mgr->ssl_use_cert_file_link = NULL;
                }
            }

            /* Phase 1: Attach SSL_CTX_use_certificate_file uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_CTX_use_certificate_file";
                opts.retprobe = false;
                mgr->ssl_ctx_use_cert_file_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_ctx_use_cert_file,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_ctx_use_cert_file_link &&
                    !libbpf_get_error(mgr->ssl_ctx_use_cert_file_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_CTX_use_certificate_file uprobe");
                } else {
                    mgr->ssl_ctx_use_cert_file_link = NULL;
                }
            }

            /* Attach SSL_use_certificate_chain_file uprobe (used by openssl s_server) */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_use_certificate_chain_file";
                opts.retprobe = false;
                mgr->ssl_use_cert_chain_file_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_use_cert_chain_file,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_use_cert_chain_file_link &&
                    !libbpf_get_error(mgr->ssl_use_cert_chain_file_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_use_certificate_chain_file uprobe");
                } else {
                    mgr->ssl_use_cert_chain_file_link = NULL;
                }
            }

            /* Attach SSL_CTX_use_certificate_chain_file uprobe (used by openssl s_server) */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_CTX_use_certificate_chain_file";
                opts.retprobe = false;
                mgr->ssl_ctx_use_cert_chain_file_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_ctx_use_cert_chain_file,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_ctx_use_cert_chain_file_link &&
                    !libbpf_get_error(mgr->ssl_ctx_use_cert_chain_file_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_CTX_use_certificate_chain_file uprobe");
                } else {
                    mgr->ssl_ctx_use_cert_chain_file_link = NULL;
                }
            }

            /* Phase 2: Attach SSL_set_fd uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_set_fd";
                opts.retprobe = false;
                mgr->ssl_set_fd_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_set_fd,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_set_fd_link &&
                    !libbpf_get_error(mgr->ssl_set_fd_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_set_fd uprobe");
                } else {
                    mgr->ssl_set_fd_link = NULL;
                }
            }

            /* Phase 3: Attach SSL_set_cipher_list uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_set_cipher_list";
                opts.retprobe = false;
                mgr->ssl_set_cipher_list_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_set_cipher_list,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_set_cipher_list_link &&
                    !libbpf_get_error(mgr->ssl_set_cipher_list_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_set_cipher_list uprobe");
                } else {
                    mgr->ssl_set_cipher_list_link = NULL;
                }
            }

            /* Phase 3: Attach SSL_CTX_set_cipher_list uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_CTX_set_cipher_list";
                opts.retprobe = false;
                mgr->ssl_ctx_set_cipher_list_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_ctx_set_cipher_list,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_ctx_set_cipher_list_link &&
                    !libbpf_get_error(mgr->ssl_ctx_set_cipher_list_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_CTX_set_cipher_list uprobe");
                } else {
                    mgr->ssl_ctx_set_cipher_list_link = NULL;
                }
            }

            /* ============================================================
             * SSL_do_handshake Probes (for Python ssl, nginx, etc.)
             *
             * Python's ssl module uses SSL_do_handshake() instead of
             * SSL_connect/SSL_accept. We track client/server mode via
             * SSL_set_connect_state/SSL_set_accept_state.
             * ============================================================ */

            /* Attach SSL_set_connect_state uprobe (client mode marker) */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_set_connect_state";
                opts.retprobe = false;
                mgr->ssl_set_connect_state_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_set_connect_state,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_set_connect_state_link &&
                    !libbpf_get_error(mgr->ssl_set_connect_state_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_set_connect_state uprobe");
                } else {
                    mgr->ssl_set_connect_state_link = NULL;
                }
            }

            /* Attach SSL_set_accept_state uprobe (server mode marker) */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_set_accept_state";
                opts.retprobe = false;
                mgr->ssl_set_accept_state_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_set_accept_state,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_set_accept_state_link &&
                    !libbpf_get_error(mgr->ssl_set_accept_state_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_set_accept_state uprobe");
                } else {
                    mgr->ssl_set_accept_state_link = NULL;
                }
            }

            /* Attach SSL_do_handshake entry uprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_do_handshake";
                opts.retprobe = false;
                mgr->ssl_do_handshake_entry_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_do_handshake_entry,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_do_handshake_entry_link &&
                    !libbpf_get_error(mgr->ssl_do_handshake_entry_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_do_handshake entry uprobe");
                } else {
                    mgr->ssl_do_handshake_entry_link = NULL;
                }
            }

            /* Attach SSL_do_handshake return uretprobe */
            {
                LIBBPF_OPTS(bpf_uprobe_opts, opts);
                opts.func_name = "SSL_do_handshake";
                opts.retprobe = true;
                mgr->ssl_do_handshake_return_link = bpf_program__attach_uprobe_opts(
                    mgr->openssl_api_skel->progs.trace_ssl_do_handshake_return,
                    -1, libssl_path, 0, &opts);
                if (mgr->ssl_do_handshake_return_link &&
                    !libbpf_get_error(mgr->ssl_do_handshake_return_link)) {
                    ssl_attached++;
                    log_debug("Attached SSL_do_handshake return uretprobe");
                } else {
                    mgr->ssl_do_handshake_return_link = NULL;
                }
            }

            if (ssl_attached > 0) {
                attached_count++;
                log_info("openssl_api_trace attached to %s (%d functions)", libssl_path, ssl_attached);
            } else {
                log_info("OpenSSL API tracing not attached (optional)");
            }
        } else {
            log_info("Could not find libssl.so path (OpenSSL tracing disabled)");
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

/* ============================================================
 * Enriched TLS Handshake Event Processor
 * Aggregates cert, socket FD, and cipher list from BPF map state
 * ============================================================ */

/**
 * Parse and process enriched TLS handshake event
 * Emitted on SSL_connect/SSL_accept completion with all accumulated context.
 * Enables single-observation correlation without user-space stitching.
 */
static int process_tls_handshake_event(struct ebpf_manager *mgr,
                                       struct ct_tls_handshake_event *event,
                                       event_callback_t callback, void *ctx)
{
    processed_event_t *proc_event;
    char timestamp[64];
    char ssl_ctx_str[20];
    char fd_str[16];
    int ret;

    proc_event = event_buffer_pool_acquire(mgr->event_pool);
    if (!proc_event) {
        mgr->events_dropped++;
        return -1;
    }

    format_timestamp(event->header.timestamp_ns, timestamp, sizeof(timestamp));

    /* Fill processed event - use "tls_handshake" as the unified event type */
    proc_event->event_type = strdup("tls_handshake");
    proc_event->timestamp = strdup(timestamp);
    proc_event->pid = event->header.pid;
    proc_event->uid = event->header.uid;
    proc_event->process = strndup(event->header.comm, MAX_COMM_LEN);

    /* Store SSL context pointer as hex string for correlation */
    snprintf(ssl_ctx_str, sizeof(ssl_ctx_str), "0x%llx",
             (unsigned long long)event->ssl_ctx);
    proc_event->library = strdup(ssl_ctx_str);

    /* Store handshake result */
    proc_event->result = event->result;

    /* Store cert path if available */
    if (event->has_cert && event->cert_path[0]) {
        proc_event->file = strndup(event->cert_path, MAX_FILENAME_LEN);
    }

    /* Store socket FD if available - in cmdline field for now */
    if (event->has_fd && event->socket_fd >= 0) {
        snprintf(fd_str, sizeof(fd_str), "fd:%d", event->socket_fd);
        proc_event->cmdline = strdup(fd_str);
    }

    /* Store cipher list if available - in function_name field for now */
    if (event->has_ciphers && event->cipher_list[0]) {
        proc_event->function_name = strndup(event->cipher_list, MAX_CIPHER_LIST_LEN);
    }

    /* Store is_client flag in flags field (reusing available field) */
    if (event->is_client) {
        proc_event->flags = strdup("client");
    } else {
        proc_event->flags = strdup("server");
    }

    ret = callback ? callback(proc_event, ctx) : 0;
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
        /* Log at debug level - events are still processed, this is informational */
        static uint64_t last_warning = 0;
        uint64_t now = header->timestamp_ns;
        if (now - last_warning > 1000000000ULL) { /* 1 second */
            log_debug("Event batch size high (%d events in poll cycle)",
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

        /* Enriched TLS handshake event (aggregated from BPF map state) */
        case CT_EVENT_TLS_HANDSHAKE:
            if (data_sz >= sizeof(struct ct_tls_handshake_event)) {
                ret = process_tls_handshake_event(mgr,
                    (struct ct_tls_handshake_event *)data,
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
 * NOTE: Each BPF program has its own ring buffer map, so we must add all of them
 * to the ring buffer manager to receive events from all programs.
 */
static int setup_ring_buffer(struct ebpf_manager *mgr, event_callback_t callback, void *ctx)
{
    int ring_buffer_fd = -1;
    int added_count = 0;

    if (!mgr) {
        return -EINVAL;
    }

    /* Allocate batch context first */
    mgr->batch_ctx = calloc(1, sizeof(*mgr->batch_ctx));
    if (!mgr->batch_ctx) {
        log_error("Failed to allocate batch context");
        return -1;
    }

    mgr->batch_ctx->mgr = mgr;
    mgr->batch_ctx->callback = callback;
    mgr->batch_ctx->user_ctx = ctx;
    mgr->batch_ctx->events_in_batch = 0;
    mgr->batch_ctx->max_batch_size = 5000; /* Warn threshold for events per poll */

    /* Create ring buffer manager with the first available ring buffer */
    if (mgr->file_open_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->file_open_skel->maps.events);
        mgr->rb = ring_buffer__new(ring_buffer_fd, handle_event, mgr->batch_ctx, NULL);
        if (mgr->rb) {
            added_count++;
            log_debug("Added file_open_trace ring buffer (fd=%d)", ring_buffer_fd);
        }
    }

    if (!mgr->rb) {
        /* Try other programs if file_open_skel wasn't available */
        if (mgr->lib_load_skel) {
            ring_buffer_fd = bpf_map__fd(mgr->lib_load_skel->maps.events);
            mgr->rb = ring_buffer__new(ring_buffer_fd, handle_event, mgr->batch_ctx, NULL);
            if (mgr->rb) {
                added_count++;
                log_debug("Added lib_load_trace ring buffer (fd=%d)", ring_buffer_fd);
            }
        }
    }

    if (!mgr->rb) {
        log_system_error("Failed to create ring buffer");
        free(mgr->batch_ctx);
        mgr->batch_ctx = NULL;
        return -1;
    }

    /* Add remaining ring buffers from other programs */
    if (mgr->lib_load_skel && added_count == 1 && mgr->file_open_skel) {
        /* lib_load wasn't the first one, add it now */
        ring_buffer_fd = bpf_map__fd(mgr->lib_load_skel->maps.events);
        if (ring_buffer__add(mgr->rb, ring_buffer_fd, handle_event, mgr->batch_ctx) == 0) {
            added_count++;
            log_debug("Added lib_load_trace ring buffer (fd=%d)", ring_buffer_fd);
        } else {
            log_warn("Failed to add lib_load_trace ring buffer");
        }
    }

    if (mgr->process_exec_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->process_exec_skel->maps.events);
        if (ring_buffer__add(mgr->rb, ring_buffer_fd, handle_event, mgr->batch_ctx) == 0) {
            added_count++;
            log_debug("Added process_exec_trace ring buffer (fd=%d)", ring_buffer_fd);
        } else {
            log_warn("Failed to add process_exec_trace ring buffer");
        }
    }

    if (mgr->process_exit_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->process_exit_skel->maps.events);
        if (ring_buffer__add(mgr->rb, ring_buffer_fd, handle_event, mgr->batch_ctx) == 0) {
            added_count++;
            log_debug("Added process_exit_trace ring buffer (fd=%d)", ring_buffer_fd);
        } else {
            log_warn("Failed to add process_exit_trace ring buffer");
        }
    }

    if (mgr->openssl_api_skel) {
        ring_buffer_fd = bpf_map__fd(mgr->openssl_api_skel->maps.events);
        if (ring_buffer__add(mgr->rb, ring_buffer_fd, handle_event, mgr->batch_ctx) == 0) {
            added_count++;
            log_debug("Added openssl_api_trace ring buffer (fd=%d)", ring_buffer_fd);
        } else {
            log_warn("Failed to add openssl_api_trace ring buffer");
        }
    }

    log_info("Ring buffer manager created with %d ring buffer(s)", added_count);

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
    
    /* Poll ring buffer with 100ms timeout
     * This will process up to max_batch_size events per call */
    err = ring_buffer__poll(mgr->rb, 100);
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
    
    return mgr->batch_ctx ? mgr->batch_ctx->events_in_batch : 0;
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

    /* Step 0: Destroy manual uprobe links first (before skeleton destruction) */
    if (mgr->ssl_accept_return_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_accept_return_link);
        mgr->ssl_accept_return_link = NULL;
    }
    if (mgr->ssl_accept_entry_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_accept_entry_link);
        mgr->ssl_accept_entry_link = NULL;
    }
    if (mgr->ssl_connect_return_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_connect_return_link);
        mgr->ssl_connect_return_link = NULL;
    }
    if (mgr->ssl_connect_entry_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_connect_entry_link);
        mgr->ssl_connect_entry_link = NULL;
    }
    if (mgr->ssl_ctx_new_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_ctx_new_link);
        mgr->ssl_ctx_new_link = NULL;
    }
    if (mgr->ssl_new_return_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_new_return_link);
        mgr->ssl_new_return_link = NULL;
    }
    if (mgr->ssl_new_entry_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_new_entry_link);
        mgr->ssl_new_entry_link = NULL;
    }

    /* State accumulation uprobe links cleanup */
    if (mgr->ssl_use_cert_file_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_use_cert_file_link);
        mgr->ssl_use_cert_file_link = NULL;
    }
    if (mgr->ssl_ctx_use_cert_file_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_ctx_use_cert_file_link);
        mgr->ssl_ctx_use_cert_file_link = NULL;
    }
    if (mgr->ssl_use_cert_chain_file_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_use_cert_chain_file_link);
        mgr->ssl_use_cert_chain_file_link = NULL;
    }
    if (mgr->ssl_ctx_use_cert_chain_file_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_ctx_use_cert_chain_file_link);
        mgr->ssl_ctx_use_cert_chain_file_link = NULL;
    }
    if (mgr->ssl_set_fd_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_set_fd_link);
        mgr->ssl_set_fd_link = NULL;
    }
    if (mgr->ssl_set_cipher_list_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_set_cipher_list_link);
        mgr->ssl_set_cipher_list_link = NULL;
    }
    if (mgr->ssl_ctx_set_cipher_list_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_ctx_set_cipher_list_link);
        mgr->ssl_ctx_set_cipher_list_link = NULL;
    }

    /* SSL_do_handshake probes cleanup */
    if (mgr->ssl_set_connect_state_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_set_connect_state_link);
        mgr->ssl_set_connect_state_link = NULL;
    }
    if (mgr->ssl_set_accept_state_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_set_accept_state_link);
        mgr->ssl_set_accept_state_link = NULL;
    }
    if (mgr->ssl_do_handshake_entry_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_do_handshake_entry_link);
        mgr->ssl_do_handshake_entry_link = NULL;
    }
    if (mgr->ssl_do_handshake_return_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->ssl_do_handshake_return_link);
        mgr->ssl_do_handshake_return_link = NULL;
    }

    if (mgr->lib_load_link && !cleanup_timeout) {
        bpf_link__destroy(mgr->lib_load_link);
        mgr->lib_load_link = NULL;
    }

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
