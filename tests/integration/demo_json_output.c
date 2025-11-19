// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * demo_json_output.c - Demonstration of JSON output formatting
 * Shows examples of all output types: events, profiles, and snapshots
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "src/include/output_formatter.h"
#include "src/include/event_processor.h"

/* Helper to create a sample timestamp */
char *create_sample_timestamp(void) {
    return format_timestamp_iso8601(1609459200000000000ULL); /* 2021-01-01T00:00:00.000000Z */
}

/* Demo 1: JSON Stream Format (compact, one event per line) */
void demo_json_stream(void) {
    printf("=== Demo 1: JSON Stream Format (Compact) ===\n");
    printf("One JSON object per line, suitable for log streaming\n\n");
    
    output_formatter_t *fmt = output_formatter_create(FORMAT_JSON_STREAM, stdout);
    
    /* File open event */
    processed_event_t event1 = {
        .event_type = "file_open",
        .timestamp = create_sample_timestamp(),
        .pid = 1234,
        .uid = 1000,
        .process = "nginx",
        .exe = "/usr/sbin/nginx",
        .file = "/etc/ssl/certs/server.crt",
        .file_type = FILE_TYPE_CERTIFICATE,
        .flags = "O_RDONLY",
        .result = 3
    };
    output_formatter_write_event(fmt, &event1);
    free(event1.timestamp);
    
    /* Library load event */
    processed_event_t event2 = {
        .event_type = "lib_load",
        .timestamp = create_sample_timestamp(),
        .pid = 1234,
        .uid = 1000,
        .process = "nginx",
        .exe = "/usr/sbin/nginx",
        .library = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        .library_name = "libssl"
    };
    output_formatter_write_event(fmt, &event2);
    free(event2.timestamp);
    
    output_formatter_destroy(fmt);
    printf("\n");
}

/* Demo 2: JSON Array Format */
void demo_json_array(void) {
    printf("=== Demo 2: JSON Array Format ===\n");
    printf("Valid JSON array, suitable for batch processing\n\n");
    
    output_formatter_t *fmt = output_formatter_create(FORMAT_JSON_ARRAY, stdout);
    
    /* Process exec event */
    processed_event_t event1 = {
        .event_type = "process_exec",
        .timestamp = create_sample_timestamp(),
        .pid = 5678,
        .uid = 1000,
        .process = "openssl",
        .exe = "/usr/bin/openssl",
        .cmdline = "openssl s_client -connect example.com:443"
    };
    output_formatter_write_event(fmt, &event1);
    free(event1.timestamp);
    
    /* API call event */
    processed_event_t event2 = {
        .event_type = "api_call",
        .timestamp = create_sample_timestamp(),
        .pid = 5678,
        .uid = 1000,
        .process = "openssl",
        .exe = "/usr/bin/openssl",
        .function_name = "SSL_connect",
        .library = "libssl"
    };
    output_formatter_write_event(fmt, &event2);
    free(event2.timestamp);
    
    /* Process exit event */
    processed_event_t event3 = {
        .event_type = "process_exit",
        .timestamp = create_sample_timestamp(),
        .pid = 5678,
        .uid = 1000,
        .process = "openssl",
        .exit_code = 0
    };
    output_formatter_write_event(fmt, &event3);
    free(event3.timestamp);
    
    output_formatter_destroy(fmt);
    printf("\n");
}

/* Demo 3: Profile Document */
void demo_profile(void) {
    printf("=== Demo 3: Profile Document (Pretty Format) ===\n");
    printf("Complete process profile with libraries, files, and statistics\n\n");
    
    output_formatter_t *fmt = output_formatter_create(FORMAT_JSON_PRETTY, stdout);
    
    /* Create sample profile */
    profile_t profile = {
        .profile_version = "1.0",
        .generated_at = create_sample_timestamp(),
        .duration_seconds = 30,
        .process = {
            .pid = 1234,
            .name = "nginx",
            .exe = "/usr/sbin/nginx",
            .cmdline = "nginx: master process /usr/sbin/nginx -g daemon off;",
            .uid = 33,
            .gid = 33,
            .start_time = create_sample_timestamp()
        },
        .library_count = 2,
        .file_count = 3,
        .api_call_count = 2,
        .statistics = {
            .total_events = 15,
            .libraries_loaded = 2,
            .files_accessed = 3,
            .api_calls_made = 10
        }
    };
    
    /* Allocate arrays */
    profile.libraries = calloc(2, sizeof(*profile.libraries));
    profile.libraries[0].name = "libssl";
    profile.libraries[0].path = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1";
    profile.libraries[0].load_time = create_sample_timestamp();
    profile.libraries[1].name = "libcrypto";
    profile.libraries[1].path = "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1";
    profile.libraries[1].load_time = create_sample_timestamp();
    
    profile.files_accessed = calloc(3, sizeof(*profile.files_accessed));
    profile.files_accessed[0].path = "/etc/ssl/certs/server.crt";
    profile.files_accessed[0].type = "certificate";
    profile.files_accessed[0].access_count = 1;
    profile.files_accessed[0].first_access = create_sample_timestamp();
    profile.files_accessed[0].last_access = create_sample_timestamp();
    profile.files_accessed[0].mode = "read";
    
    profile.files_accessed[1].path = "/etc/ssl/private/server.key";
    profile.files_accessed[1].type = "private_key";
    profile.files_accessed[1].access_count = 1;
    profile.files_accessed[1].first_access = create_sample_timestamp();
    profile.files_accessed[1].last_access = create_sample_timestamp();
    profile.files_accessed[1].mode = "read";
    
    profile.files_accessed[2].path = "/etc/ssl/certs/ca-bundle.crt";
    profile.files_accessed[2].type = "certificate";
    profile.files_accessed[2].access_count = 5;
    profile.files_accessed[2].first_access = create_sample_timestamp();
    profile.files_accessed[2].last_access = create_sample_timestamp();
    profile.files_accessed[2].mode = "read";
    
    profile.api_calls = calloc(2, sizeof(*profile.api_calls));
    profile.api_calls[0].function_name = "SSL_CTX_new";
    profile.api_calls[0].count = 1;
    profile.api_calls[1].function_name = "SSL_accept";
    profile.api_calls[1].count = 9;
    
    output_formatter_write_profile(fmt, &profile);
    
    /* Cleanup */
    free(profile.generated_at);
    free(profile.process.start_time);
    for (size_t i = 0; i < profile.library_count; i++) {
        free(profile.libraries[i].load_time);
    }
    free(profile.libraries);
    for (size_t i = 0; i < profile.file_count; i++) {
        free(profile.files_accessed[i].first_access);
        free(profile.files_accessed[i].last_access);
    }
    free(profile.files_accessed);
    free(profile.api_calls);
    
    output_formatter_destroy(fmt);
    printf("\n");
}

/* Demo 4: Snapshot Document */
void demo_snapshot(void) {
    printf("=== Demo 4: Snapshot Document (Pretty Format) ===\n");
    printf("System-wide crypto inventory with all processes\n\n");
    
    output_formatter_t *fmt = output_formatter_create(FORMAT_JSON_PRETTY, stdout);
    
    /* Create sample snapshot */
    snapshot_t snapshot = {
        .snapshot_version = "1.0",
        .generated_at = create_sample_timestamp(),
        .hostname = "web-server-01",
        .kernel = "5.15.0-generic",
        .process_count = 2,
        .summary = {
            .total_processes = 2,
            .total_libraries = 3,
            .total_files = 2
        }
    };
    
    /* Allocate processes array */
    snapshot.processes = calloc(2, sizeof(*snapshot.processes));
    
    /* Process 1: nginx */
    snapshot.processes[0].pid = 1234;
    snapshot.processes[0].name = "nginx";
    snapshot.processes[0].exe = "/usr/sbin/nginx";
    snapshot.processes[0].running_as = "www-data";
    snapshot.processes[0].library_count = 2;
    snapshot.processes[0].libraries = calloc(2, sizeof(char*));
    snapshot.processes[0].libraries[0] = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1";
    snapshot.processes[0].libraries[1] = "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1";
    snapshot.processes[0].file_count = 2;
    snapshot.processes[0].open_crypto_files = calloc(2, sizeof(char*));
    snapshot.processes[0].open_crypto_files[0] = "/etc/ssl/certs/server.crt";
    snapshot.processes[0].open_crypto_files[1] = "/etc/ssl/private/server.key";
    
    /* Process 2: postgres */
    snapshot.processes[1].pid = 5678;
    snapshot.processes[1].name = "postgres";
    snapshot.processes[1].exe = "/usr/lib/postgresql/14/bin/postgres";
    snapshot.processes[1].running_as = "postgres";
    snapshot.processes[1].library_count = 1;
    snapshot.processes[1].libraries = calloc(1, sizeof(char*));
    snapshot.processes[1].libraries[0] = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1";
    snapshot.processes[1].file_count = 0;
    snapshot.processes[1].open_crypto_files = NULL;
    
    output_formatter_write_snapshot(fmt, &snapshot);
    
    /* Cleanup */
    free(snapshot.generated_at);
    for (size_t i = 0; i < snapshot.process_count; i++) {
        free(snapshot.processes[i].libraries);
        free(snapshot.processes[i].open_crypto_files);
    }
    free(snapshot.processes);
    
    output_formatter_destroy(fmt);
    printf("\n");
}

int main(void) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║         crypto-tracer JSON Output Demonstration           ║\n");
    printf("║                                                            ║\n");
    printf("║  This demo shows all JSON output formats supported by     ║\n");
    printf("║  crypto-tracer for events, profiles, and snapshots.       ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    demo_json_stream();
    printf("────────────────────────────────────────────────────────────\n\n");
    
    demo_json_array();
    printf("────────────────────────────────────────────────────────────\n\n");
    
    demo_profile();
    printf("────────────────────────────────────────────────────────────\n\n");
    
    demo_snapshot();
    
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║                    Demo Complete!                          ║\n");
    printf("║                                                            ║\n");
    printf("║  All JSON output is valid and can be parsed by standard   ║\n");
    printf("║  JSON parsers like jq, Python's json module, etc.         ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}
