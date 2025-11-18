// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * event_buffer.c - Event buffer pool implementation
 * Pre-allocated event buffer pool to avoid malloc in hot path
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "include/crypto_tracer.h"
#include "include/logger.h"

/* Default buffer pool capacity */
#define DEFAULT_POOL_CAPACITY 1000

/**
 * Create a new event buffer pool with specified capacity
 * Requirement: 17.1, 17.2, 17.3, 17.4
 * 
 * @param capacity Number of events to pre-allocate
 * @return Pointer to event buffer pool, or NULL on failure
 */
event_buffer_pool_t *event_buffer_pool_create(size_t capacity) {
    event_buffer_pool_t *pool = NULL;
    size_t i;
    
    if (capacity == 0) {
        capacity = DEFAULT_POOL_CAPACITY;
    }
    
    /* Allocate pool structure */
    pool = (event_buffer_pool_t *)calloc(1, sizeof(event_buffer_pool_t));
    if (!pool) {
        log_error("Failed to allocate event buffer pool");
        return NULL;
    }
    
    /* Allocate event array */
    pool->events = (processed_event_t *)calloc(capacity, sizeof(processed_event_t));
    if (!pool->events) {
        log_error("Failed to allocate event buffer array");
        free(pool);
        return NULL;
    }
    
    log_debug("Event buffer pool created with capacity: %zu", capacity);
    
    pool->capacity = capacity;
    pool->in_use_count = 0;
    pool->free_list = NULL;
    
    /* Initialize free list - link all events together */
    for (i = 0; i < capacity; i++) {
        pool->events[i].in_use = false;
        pool->events[i].next = pool->free_list;
        pool->free_list = &pool->events[i];
    }
    
    return pool;
}

/**
 * Acquire an event from the buffer pool
 * Returns a pre-allocated event, or NULL if pool is exhausted
 * 
 * @param pool Event buffer pool
 * @return Pointer to available event, or NULL if none available
 */
processed_event_t *event_buffer_pool_acquire(event_buffer_pool_t *pool) {
    processed_event_t *event = NULL;
    
    if (!pool) {
        return NULL;
    }
    
    /* Check if free list is empty */
    if (!pool->free_list) {
        log_warn("Event buffer pool exhausted (%zu events in use)", pool->in_use_count);
        return NULL;
    }
    
    /* Pop from free list */
    event = pool->free_list;
    pool->free_list = event->next;
    
    /* Clear the event structure */
    memset(event, 0, sizeof(processed_event_t));
    event->in_use = true;
    event->next = NULL;
    
    pool->in_use_count++;
    
    return event;
}

/**
 * Release an event back to the buffer pool
 * Frees any dynamically allocated strings and returns event to free list
 * 
 * @param pool Event buffer pool
 * @param event Event to release
 */
void event_buffer_pool_release(event_buffer_pool_t *pool, processed_event_t *event) {
    if (!pool || !event) {
        return;
    }
    
    /* Verify this event belongs to this pool */
    if (event < pool->events || event >= pool->events + pool->capacity) {
        log_warn("Attempted to release event not from this pool");
        return;
    }
    
    if (!event->in_use) {
        log_warn("Attempted to release event that is not in use");
        return;
    }
    
    /* Free any dynamically allocated strings */
    free(event->event_type);
    free(event->timestamp);
    free(event->process);
    free(event->exe);
    free(event->cmdline);
    free(event->file);
    free(event->library);
    free(event->library_name);
    free(event->function_name);
    free(event->flags);
    
    /* Clear the event structure */
    memset(event, 0, sizeof(processed_event_t));
    
    /* Return to free list */
    event->in_use = false;
    event->next = pool->free_list;
    pool->free_list = event;
    
    pool->in_use_count--;
}

/**
 * Destroy event buffer pool and free all resources
 * 
 * @param pool Event buffer pool to destroy
 */
void event_buffer_pool_destroy(event_buffer_pool_t *pool) {
    size_t i;
    
    if (!pool) {
        return;
    }
    
    /* Free any strings in events that are still in use */
    if (pool->events) {
        for (i = 0; i < pool->capacity; i++) {
            if (pool->events[i].in_use) {
                /* Free dynamically allocated strings */
                free(pool->events[i].event_type);
                free(pool->events[i].timestamp);
                free(pool->events[i].process);
                free(pool->events[i].exe);
                free(pool->events[i].cmdline);
                free(pool->events[i].file);
                free(pool->events[i].library);
                free(pool->events[i].library_name);
                free(pool->events[i].function_name);
                free(pool->events[i].flags);
            }
        }
        free(pool->events);
    }
    
    free(pool);
}
