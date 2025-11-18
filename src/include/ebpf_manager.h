/* ebpf_manager.h - eBPF program management
 * Copyright (C) 2024
 */

#ifndef __EBPF_MANAGER_H__
#define __EBPF_MANAGER_H__

#include <stdint.h>
#include <stdbool.h>

/* Forward declarations */
struct ebpf_manager;
struct processed_event;

/* Event callback function type */
typedef int (*event_callback_t)(struct processed_event *event, void *ctx);

/* Function prototypes */
struct ebpf_manager *ebpf_manager_create(void);
int ebpf_manager_load_programs(struct ebpf_manager *mgr);
int ebpf_manager_attach_programs(struct ebpf_manager *mgr);
int ebpf_manager_poll_events(struct ebpf_manager *mgr, event_callback_t callback, void *ctx);
void ebpf_manager_cleanup(struct ebpf_manager *mgr);
void ebpf_manager_destroy(struct ebpf_manager *mgr);
void ebpf_manager_get_stats(struct ebpf_manager *mgr, uint64_t *events_processed, uint64_t *events_dropped);

#endif /* __EBPF_MANAGER_H__ */