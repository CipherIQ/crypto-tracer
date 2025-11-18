// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * profile_manager.h - Profile management interface
 * Handles incremental profile building during monitoring
 * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
 */

#ifndef __PROFILE_MANAGER_H__
#define __PROFILE_MANAGER_H__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include "crypto_tracer.h"

/* Forward declaration */
typedef struct profile_manager profile_manager_t;

/* Profile manager lifecycle functions */
profile_manager_t *profile_manager_create(void);
void profile_manager_destroy(profile_manager_t *mgr);

/* Event aggregation functions */
int profile_manager_add_event(profile_manager_t *mgr, processed_event_t *event);

/* Profile retrieval and finalization */
profile_t *profile_manager_get_profile(profile_manager_t *mgr, pid_t pid);
profile_t *profile_manager_finalize_profile(profile_manager_t *mgr, pid_t pid, int duration_seconds);

/* Profile cleanup */
void profile_free(profile_t *profile);

#endif /* __PROFILE_MANAGER_H__ */
