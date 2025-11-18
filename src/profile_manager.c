// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * profile_manager.c - Profile management implementation
 * Handles incremental profile building during monitoring
 * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
 */

/* Enable POSIX features for strdup */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include "profile_manager.h"
#include "crypto_tracer.h"
#include "output_formatter.h"
#include "event_processor.h"

/* Maximum number of tracked profiles */
#define MAX_TRACKED_PROFILES 1000

/* Internal library entry */
typedef struct library_entry {
    char *name;
    char *path;
    char *load_time;
    struct library_entry *next;
} library_entry_t;

/* Internal file entry */
typedef struct file_entry {
    char *path;
    char *type;
    int access_count;
    char *first_access;
    char *last_access;
    char *mode;
    struct file_entry *next;
} file_entry_t;

/* Internal API call entry */
typedef struct api_call_entry {
    char *function_name;
    int count;
    struct api_call_entry *next;
} api_call_entry_t;

/* Internal profile tracking structure */
typedef struct tracked_profile {
    pid_t pid;
    bool active;
    time_t last_update;
    
    /* Process metadata */
    char *process_name;
    char *exe;
    char *cmdline;
    uint32_t uid;
    uint32_t gid;
    char *start_time;
    
    /* Aggregated data (linked lists for dynamic growth) */
    library_entry_t *libraries;
    size_t library_count;
    
    file_entry_t *files;
    size_t file_count;
    
    api_call_entry_t *api_calls;
    size_t api_call_count;
    
    /* Statistics */
    int total_events;
    int libraries_loaded;
    int files_accessed;
    int api_calls_made;
} tracked_profile_t;

/* Profile manager structure */
struct profile_manager {
    tracked_profile_t *profiles;
    size_t count;
    size_t capacity;
};

/**
 * Create a new profile manager
 */
profile_manager_t *profile_manager_create(void) {
    profile_manager_t *mgr = calloc(1, sizeof(profile_manager_t));
    if (!mgr) {
        return NULL;
    }
    
    mgr->capacity = MAX_TRACKED_PROFILES;
    mgr->profiles = calloc(mgr->capacity, sizeof(tracked_profile_t));
    if (!mgr->profiles) {
        free(mgr);
        return NULL;
    }
    
    mgr->count = 0;
    return mgr;
}

/**
 * Find or create a tracked profile for a given PID
 */
static tracked_profile_t *find_or_create_profile(profile_manager_t *mgr, pid_t pid) {
    if (!mgr) {
        return NULL;
    }
    
    /* Search for existing profile */
    for (size_t i = 0; i < mgr->count; i++) {
        if (mgr->profiles[i].pid == pid && mgr->profiles[i].active) {
            return &mgr->profiles[i];
        }
    }
    
    /* Create new profile if space available */
    if (mgr->count >= mgr->capacity) {
        return NULL;  /* No space for new profiles */
    }
    
    tracked_profile_t *profile = &mgr->profiles[mgr->count++];
    memset(profile, 0, sizeof(tracked_profile_t));
    profile->pid = pid;
    profile->active = true;
    profile->last_update = time(NULL);
    
    return profile;
}

/**
 * Add a library to the profile (deduplicate by path)
 */
static int add_library(tracked_profile_t *profile, const char *name, const char *path, const char *timestamp) {
    if (!profile || !path) {
        return -1;
    }
    
    /* Check if library already exists */
    library_entry_t *entry = profile->libraries;
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            return 0;  /* Already exists, skip */
        }
        entry = entry->next;
    }
    
    /* Create new library entry */
    entry = calloc(1, sizeof(library_entry_t));
    if (!entry) {
        return -1;
    }
    
    entry->name = name ? strdup(name) : NULL;
    entry->path = strdup(path);
    entry->load_time = timestamp ? strdup(timestamp) : NULL;
    
    /* Add to front of list */
    entry->next = profile->libraries;
    profile->libraries = entry;
    profile->library_count++;
    profile->libraries_loaded++;
    
    return 0;
}

/**
 * Add or update a file in the profile
 */
static int add_or_update_file(tracked_profile_t *profile, const char *path, const char *type, 
                               const char *timestamp, const char *mode) {
    if (!profile || !path) {
        return -1;
    }
    
    /* Check if file already exists */
    file_entry_t *entry = profile->files;
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            /* Update existing entry */
            entry->access_count++;
            if (entry->last_access) {
                free(entry->last_access);
            }
            entry->last_access = timestamp ? strdup(timestamp) : NULL;
            return 0;
        }
        entry = entry->next;
    }
    
    /* Create new file entry */
    entry = calloc(1, sizeof(file_entry_t));
    if (!entry) {
        return -1;
    }
    
    entry->path = strdup(path);
    entry->type = type ? strdup(type) : strdup("unknown");
    entry->access_count = 1;
    entry->first_access = timestamp ? strdup(timestamp) : NULL;
    entry->last_access = timestamp ? strdup(timestamp) : NULL;
    entry->mode = mode ? strdup(mode) : NULL;
    
    /* Add to front of list */
    entry->next = profile->files;
    profile->files = entry;
    profile->file_count++;
    profile->files_accessed++;
    
    return 0;
}

/**
 * Add or update an API call in the profile
 */
static int add_or_update_api_call(tracked_profile_t *profile, const char *function_name) {
    if (!profile || !function_name) {
        return -1;
    }
    
    /* Check if API call already exists */
    api_call_entry_t *entry = profile->api_calls;
    while (entry) {
        if (strcmp(entry->function_name, function_name) == 0) {
            /* Update existing entry */
            entry->count++;
            return 0;
        }
        entry = entry->next;
    }
    
    /* Create new API call entry */
    entry = calloc(1, sizeof(api_call_entry_t));
    if (!entry) {
        return -1;
    }
    
    entry->function_name = strdup(function_name);
    entry->count = 1;
    
    /* Add to front of list */
    entry->next = profile->api_calls;
    profile->api_calls = entry;
    profile->api_call_count++;
    profile->api_calls_made++;
    
    return 0;
}

/**
 * Add an event to the profile manager
 */
int profile_manager_add_event(profile_manager_t *mgr, processed_event_t *event) {
    if (!mgr || !event) {
        return -1;
    }
    
    tracked_profile_t *profile = find_or_create_profile(mgr, event->pid);
    if (!profile) {
        return -1;  /* Failed to find or create profile */
    }
    
    /* Update last update time */
    profile->last_update = time(NULL);
    profile->total_events++;
    
    /* Update process metadata if not set */
    if (!profile->process_name && event->process) {
        profile->process_name = strdup(event->process);
    }
    if (!profile->exe && event->exe) {
        profile->exe = strdup(event->exe);
    }
    if (!profile->cmdline && event->cmdline) {
        profile->cmdline = strdup(event->cmdline);
    }
    if (!profile->start_time && event->timestamp) {
        profile->start_time = strdup(event->timestamp);
    }
    
    profile->uid = event->uid;
    
    /* Process event based on type */
    if (event->event_type) {
        if (strcmp(event->event_type, "lib_load") == 0) {
            /* Library load event */
            if (event->library) {
                add_library(profile, event->library_name, event->library, event->timestamp);
            }
        } else if (strcmp(event->event_type, "file_open") == 0) {
            /* File open event */
            if (event->file) {
                const char *file_type_str = file_type_to_string(event->file_type);
                add_or_update_file(profile, event->file, file_type_str, event->timestamp, event->flags);
            }
        } else if (strcmp(event->event_type, "api_call") == 0) {
            /* API call event */
            if (event->function_name) {
                add_or_update_api_call(profile, event->function_name);
            }
        }
    }
    
    return 0;
}

/**
 * Convert internal profile to external profile_t structure
 */
static profile_t *convert_to_profile_t(tracked_profile_t *tracked, int duration_seconds) {
    if (!tracked) {
        return NULL;
    }
    
    profile_t *profile = calloc(1, sizeof(profile_t));
    if (!profile) {
        return NULL;
    }
    
    /* Set version and metadata */
    profile->profile_version = strdup("1.0");
    profile->generated_at = format_timestamp_iso8601(time(NULL) * 1000000000ULL);
    profile->duration_seconds = duration_seconds;
    
    /* Set process metadata */
    profile->process.pid = tracked->pid;
    profile->process.name = tracked->process_name ? strdup(tracked->process_name) : NULL;
    profile->process.exe = tracked->exe ? strdup(tracked->exe) : NULL;
    profile->process.cmdline = tracked->cmdline ? strdup(tracked->cmdline) : NULL;
    profile->process.uid = tracked->uid;
    profile->process.gid = tracked->gid;
    profile->process.start_time = tracked->start_time ? strdup(tracked->start_time) : NULL;
    
    /* Convert libraries */
    profile->library_count = tracked->library_count;
    if (profile->library_count > 0) {
        profile->libraries = calloc(profile->library_count, sizeof(profile->libraries[0]));
        if (profile->libraries) {
            library_entry_t *lib = tracked->libraries;
            size_t idx = 0;
            while (lib && idx < profile->library_count) {
                profile->libraries[idx].name = lib->name ? strdup(lib->name) : NULL;
                profile->libraries[idx].path = lib->path ? strdup(lib->path) : NULL;
                profile->libraries[idx].load_time = lib->load_time ? strdup(lib->load_time) : NULL;
                lib = lib->next;
                idx++;
            }
        }
    }
    
    /* Convert files */
    profile->file_count = tracked->file_count;
    if (profile->file_count > 0) {
        profile->files_accessed = calloc(profile->file_count, sizeof(profile->files_accessed[0]));
        if (profile->files_accessed) {
            file_entry_t *file = tracked->files;
            size_t idx = 0;
            while (file && idx < profile->file_count) {
                profile->files_accessed[idx].path = file->path ? strdup(file->path) : NULL;
                profile->files_accessed[idx].type = file->type ? strdup(file->type) : NULL;
                profile->files_accessed[idx].access_count = file->access_count;
                profile->files_accessed[idx].first_access = file->first_access ? strdup(file->first_access) : NULL;
                profile->files_accessed[idx].last_access = file->last_access ? strdup(file->last_access) : NULL;
                profile->files_accessed[idx].mode = file->mode ? strdup(file->mode) : NULL;
                file = file->next;
                idx++;
            }
        }
    }
    
    /* Convert API calls */
    profile->api_call_count = tracked->api_call_count;
    if (profile->api_call_count > 0) {
        profile->api_calls = calloc(profile->api_call_count, sizeof(profile->api_calls[0]));
        if (profile->api_calls) {
            api_call_entry_t *api = tracked->api_calls;
            size_t idx = 0;
            while (api && idx < profile->api_call_count) {
                profile->api_calls[idx].function_name = api->function_name ? strdup(api->function_name) : NULL;
                profile->api_calls[idx].count = api->count;
                api = api->next;
                idx++;
            }
        }
    }
    
    /* Set statistics */
    profile->statistics.total_events = tracked->total_events;
    profile->statistics.libraries_loaded = tracked->libraries_loaded;
    profile->statistics.files_accessed = tracked->files_accessed;
    profile->statistics.api_calls_made = tracked->api_calls_made;
    
    return profile;
}

/**
 * Get a profile for a specific PID (without finalizing)
 */
profile_t *profile_manager_get_profile(profile_manager_t *mgr, pid_t pid) {
    if (!mgr) {
        return NULL;
    }
    
    /* Find the profile */
    for (size_t i = 0; i < mgr->count; i++) {
        if (mgr->profiles[i].pid == pid && mgr->profiles[i].active) {
            return convert_to_profile_t(&mgr->profiles[i], 0);
        }
    }
    
    return NULL;
}

/**
 * Finalize a profile for a specific PID
 */
profile_t *profile_manager_finalize_profile(profile_manager_t *mgr, pid_t pid, int duration_seconds) {
    if (!mgr) {
        return NULL;
    }
    
    /* Find the profile */
    for (size_t i = 0; i < mgr->count; i++) {
        if (mgr->profiles[i].pid == pid && mgr->profiles[i].active) {
            profile_t *profile = convert_to_profile_t(&mgr->profiles[i], duration_seconds);
            mgr->profiles[i].active = false;  /* Mark as finalized */
            return profile;
        }
    }
    
    return NULL;
}

/**
 * Free a profile structure
 */
void profile_free(profile_t *profile) {
    if (!profile) {
        return;
    }
    
    /* Free top-level strings */
    free(profile->profile_version);
    free(profile->generated_at);
    
    /* Free process metadata */
    free(profile->process.name);
    free(profile->process.exe);
    free(profile->process.cmdline);
    free(profile->process.start_time);
    
    /* Free libraries */
    if (profile->libraries) {
        for (size_t i = 0; i < profile->library_count; i++) {
            free(profile->libraries[i].name);
            free(profile->libraries[i].path);
            free(profile->libraries[i].load_time);
        }
        free(profile->libraries);
    }
    
    /* Free files */
    if (profile->files_accessed) {
        for (size_t i = 0; i < profile->file_count; i++) {
            free(profile->files_accessed[i].path);
            free(profile->files_accessed[i].type);
            free(profile->files_accessed[i].first_access);
            free(profile->files_accessed[i].last_access);
            free(profile->files_accessed[i].mode);
        }
        free(profile->files_accessed);
    }
    
    /* Free API calls */
    if (profile->api_calls) {
        for (size_t i = 0; i < profile->api_call_count; i++) {
            free(profile->api_calls[i].function_name);
        }
        free(profile->api_calls);
    }
    
    free(profile);
}

/**
 * Free internal tracked profile data
 */
static void free_tracked_profile(tracked_profile_t *profile) {
    if (!profile) {
        return;
    }
    
    /* Free process metadata */
    free(profile->process_name);
    free(profile->exe);
    free(profile->cmdline);
    free(profile->start_time);
    
    /* Free libraries */
    library_entry_t *lib = profile->libraries;
    while (lib) {
        library_entry_t *next = lib->next;
        free(lib->name);
        free(lib->path);
        free(lib->load_time);
        free(lib);
        lib = next;
    }
    
    /* Free files */
    file_entry_t *file = profile->files;
    while (file) {
        file_entry_t *next = file->next;
        free(file->path);
        free(file->type);
        free(file->first_access);
        free(file->last_access);
        free(file->mode);
        free(file);
        file = next;
    }
    
    /* Free API calls */
    api_call_entry_t *api = profile->api_calls;
    while (api) {
        api_call_entry_t *next = api->next;
        free(api->function_name);
        free(api);
        api = next;
    }
}

/**
 * Destroy the profile manager and free all resources
 */
void profile_manager_destroy(profile_manager_t *mgr) {
    if (!mgr) {
        return;
    }
    
    /* Free all tracked profiles */
    if (mgr->profiles) {
        for (size_t i = 0; i < mgr->count; i++) {
            free_tracked_profile(&mgr->profiles[i]);
        }
        free(mgr->profiles);
    }
    
    free(mgr);
}
