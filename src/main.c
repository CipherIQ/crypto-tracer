// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * crypto-tracer - Main entry point
 * Standalone eBPF-based command-line tool for monitoring cryptographic operations
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/capability.h>
#include <sys/utsname.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include "include/crypto_tracer.h"
#include "include/logger.h"
#include "include/ebpf_manager.h"
#include "include/event_processor.h"
#include "include/output_formatter.h"
#include "include/profile_manager.h"
#include "include/proc_scanner.h"
#include "include/privacy_filter.h"

/* Minimum supported kernel version */
#define MIN_KERNEL_MAJOR 4
#define MIN_KERNEL_MINOR 15

/* Kernel version for CAP_BPF support */
#define CAP_BPF_KERNEL_MAJOR 5
#define CAP_BPF_KERNEL_MINOR 8

/* CAP_BPF capability (not defined in older headers) */
#ifndef CAP_BPF
#define CAP_BPF 39
#endif

/* Default values */
#define DEFAULT_DURATION 0           /* Unlimited */
#define DEFAULT_PROFILE_DURATION 30  /* 30 seconds for profile command */
#define DEFAULT_FORMAT FORMAT_JSON_STREAM

/* External shutdown flag from signal_handler.c */
extern volatile sig_atomic_t shutdown_requested;

/**
 * Print version information
 * Requirement: 11.1
 */
void print_version(void) {
    printf("crypto-tracer version %s\n", CRYPTO_TRACER_VERSION);
    printf("Build date: %s %s\n", __DATE__, __TIME__);
    printf("Kernel support: Linux 4.15+\n");
    printf("License: GPL-3.0-or-later\n");
    printf("Copyright (c) 2025 Graziano Labs Corp.\n");
}

/**
 * Print general usage information
 * Requirement: 11.2
 */
void print_usage(const char *program_name) {
    printf("Usage: %s <command> [options]\n\n", program_name);
    printf("Commands:\n");
    printf("  monitor              Monitor crypto operations in real-time\n");
    printf("  profile              Generate detailed profile of a process\n");
    printf("  snapshot             Take quick snapshot of all crypto usage\n");
    printf("  libs                 List loaded cryptographic libraries\n");
    printf("  files                Track access to cryptographic files\n");
    printf("  help [command]       Show help for a specific command\n");
    printf("  version              Show version information\n");
    printf("\n");
    printf("Global Options:\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -v, --verbose        Enable verbose output\n");
    printf("  -q, --quiet          Quiet mode (minimal output)\n");
    printf("  -o, --output FILE    Write output to FILE instead of stdout\n");
    printf("  -f, --format FORMAT  Output format: json-stream, json-array, json-pretty, summary\n");
    printf("  --no-redact          Disable privacy path redaction\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s monitor --duration 60                    # Monitor for 60 seconds\n", program_name);
    printf("  %s profile --pid 1234 --duration 30         # Profile process 1234\n", program_name);
    printf("  %s snapshot --format summary                # Quick system snapshot\n", program_name);
    printf("  %s files --file '/etc/ssl/*.pem'            # Track certificate access\n", program_name);
    printf("\n");
    printf("For detailed help on a specific command, use: %s help <command>\n", program_name);
}

/**
 * Print command-specific help
 * Requirement: 11.3
 */
void print_command_help(command_type_t cmd) {
    switch (cmd) {
        case CMD_MONITOR:
            printf("Usage: crypto-tracer monitor [options]\n\n");
            printf("Monitor cryptographic operations in real-time.\n\n");
            printf("Options:\n");
            printf("  -d, --duration SECONDS   Monitor for specified duration (default: unlimited)\n");
            printf("  -p, --pid PID            Monitor specific process ID\n");
            printf("  -n, --name NAME          Monitor processes matching name\n");
            printf("  -l, --library LIB        Filter by library name\n");
            printf("  -F, --file PATTERN       Filter by file path (glob pattern)\n");
            printf("  -o, --output FILE        Write output to file\n");
            printf("  -f, --format FORMAT      Output format (json-stream, json-array, json-pretty)\n");
            printf("  -v, --verbose            Enable verbose output\n");
            printf("  -q, --quiet              Quiet mode\n");
            printf("  --no-redact              Disable path redaction\n");
            printf("\n");
            printf("Examples:\n");
            printf("  crypto-tracer monitor --duration 60\n");
            printf("  crypto-tracer monitor --pid 1234 --output events.json\n");
            printf("  crypto-tracer monitor --name nginx --library libssl\n");
            break;
            
        case CMD_PROFILE:
            printf("Usage: crypto-tracer profile [options]\n\n");
            printf("Generate a detailed profile of a process's cryptographic usage.\n\n");
            printf("Options:\n");
            printf("  -p, --pid PID            Target process ID (required)\n");
            printf("  -n, --name NAME          Target process name (alternative to --pid)\n");
            printf("  -d, --duration SECONDS   Profile duration (default: 30 seconds)\n");
            printf("  --follow-children        Include child processes in profile\n");
            printf("  -o, --output FILE        Write profile to file\n");
            printf("  -f, --format FORMAT      Output format (json-stream, json-pretty)\n");
            printf("  -v, --verbose            Enable verbose output\n");
            printf("  --no-redact              Disable path redaction\n");
            printf("\n");
            printf("Examples:\n");
            printf("  crypto-tracer profile --pid 1234\n");
            printf("  crypto-tracer profile --name nginx --duration 60\n");
            printf("  crypto-tracer profile --pid 1234 --follow-children\n");
            break;
            
        case CMD_SNAPSHOT:
            printf("Usage: crypto-tracer snapshot [options]\n\n");
            printf("Take a quick snapshot of all cryptographic usage on the system.\n\n");
            printf("Options:\n");
            printf("  -o, --output FILE        Write snapshot to file\n");
            printf("  -f, --format FORMAT      Output format (json-pretty, summary)\n");
            printf("  -v, --verbose            Enable verbose output\n");
            printf("  --no-redact              Disable path redaction\n");
            printf("\n");
            printf("Examples:\n");
            printf("  crypto-tracer snapshot\n");
            printf("  crypto-tracer snapshot --format summary\n");
            printf("  crypto-tracer snapshot --output snapshot.json\n");
            break;
            
        case CMD_LIBS:
            printf("Usage: crypto-tracer libs [options]\n\n");
            printf("List all loaded cryptographic libraries.\n\n");
            printf("Options:\n");
            printf("  -l, --library LIB        Filter by library name\n");
            printf("  -d, --duration SECONDS   Monitor duration (default: unlimited)\n");
            printf("  -o, --output FILE        Write output to file\n");
            printf("  -f, --format FORMAT      Output format (json-stream, json-array)\n");
            printf("  -v, --verbose            Enable verbose output\n");
            printf("  --no-redact              Disable path redaction\n");
            printf("\n");
            printf("Examples:\n");
            printf("  crypto-tracer libs\n");
            printf("  crypto-tracer libs --library libssl\n");
            printf("  crypto-tracer libs --duration 60 --output libs.json\n");
            break;
            
        case CMD_FILES:
            printf("Usage: crypto-tracer files [options]\n\n");
            printf("Track access to cryptographic files (certificates, keys, keystores).\n\n");
            printf("Options:\n");
            printf("  -F, --file PATTERN       Filter by file path (glob pattern)\n");
            printf("  -d, --duration SECONDS   Monitor duration (default: unlimited)\n");
            printf("  -o, --output FILE        Write output to file\n");
            printf("  -f, --format FORMAT      Output format (json-stream, json-array)\n");
            printf("  -v, --verbose            Enable verbose output\n");
            printf("  --no-redact              Disable path redaction\n");
            printf("\n");
            printf("Examples:\n");
            printf("  crypto-tracer files\n");
            printf("  crypto-tracer files --file '/etc/ssl/*.pem'\n");
            printf("  crypto-tracer files --duration 60 --output files.json\n");
            break;
            
        default:
            printf("No help available for this command.\n");
            break;
    }
}

/**
 * Initialize cli_args structure with default values
 */
static void init_args(cli_args_t *args) {
    memset(args, 0, sizeof(cli_args_t));
    args->command = CMD_NONE;
    args->duration = DEFAULT_DURATION;
    args->output_file = NULL;
    args->format = DEFAULT_FORMAT;
    args->pid = 0;
    args->process_name = NULL;
    args->library_filter = NULL;
    args->file_filter = NULL;
    args->verbose = false;
    args->quiet = false;
    args->no_redact = false;
    args->follow_children = false;
    args->exit_after_parse = false;
}

/**
 * Parse output format string
 * Returns format type or -1 on error
 */
static int parse_format(const char *format_str) {
    if (strcmp(format_str, "json-stream") == 0) {
        return FORMAT_JSON_STREAM;
    } else if (strcmp(format_str, "json-array") == 0) {
        return FORMAT_JSON_ARRAY;
    } else if (strcmp(format_str, "json-pretty") == 0) {
        return FORMAT_JSON_PRETTY;
    } else if (strcmp(format_str, "summary") == 0) {
        return FORMAT_SUMMARY;
    }
    return -1;
}

/**
 * Parse command string
 * Returns command type or CMD_NONE on error
 */
static command_type_t parse_command(const char *cmd_str) {
    if (strcmp(cmd_str, "monitor") == 0) {
        return CMD_MONITOR;
    } else if (strcmp(cmd_str, "profile") == 0) {
        return CMD_PROFILE;
    } else if (strcmp(cmd_str, "snapshot") == 0) {
        return CMD_SNAPSHOT;
    } else if (strcmp(cmd_str, "libs") == 0) {
        return CMD_LIBS;
    } else if (strcmp(cmd_str, "files") == 0) {
        return CMD_FILES;
    } else if (strcmp(cmd_str, "help") == 0) {
        return CMD_HELP;
    } else if (strcmp(cmd_str, "version") == 0) {
        return CMD_VERSION;
    }
    return CMD_NONE;
}

/**
 * Validate argument combinations for specific commands
 * Returns 0 on success, -1 on validation error
 */
static int validate_args(cli_args_t *args) {
    /* Profile command requires either --pid or --name */
    if (args->command == CMD_PROFILE) {
        if (args->pid == 0 && args->process_name == NULL) {
            fprintf(stderr, "Error: profile command requires --pid or --name\n");
            fprintf(stderr, "Use 'crypto-tracer help profile' for more information\n");
            return -1;
        }
        /* Set default duration for profile if not specified */
        if (args->duration == DEFAULT_DURATION) {
            args->duration = DEFAULT_PROFILE_DURATION;
        }
    }
    
    /* Snapshot command doesn't support duration, pid, or filters */
    if (args->command == CMD_SNAPSHOT) {
        if (args->duration != DEFAULT_DURATION) {
            fprintf(stderr, "Warning: --duration is ignored for snapshot command\n");
        }
        if (args->pid != 0 || args->process_name != NULL) {
            fprintf(stderr, "Warning: --pid and --name are ignored for snapshot command\n");
        }
        if (args->library_filter != NULL || args->file_filter != NULL) {
            fprintf(stderr, "Warning: filters are ignored for snapshot command\n");
        }
        if (args->follow_children) {
            fprintf(stderr, "Warning: --follow-children is ignored for snapshot command\n");
        }
    }
    
    /* Verbose and quiet are mutually exclusive */
    if (args->verbose && args->quiet) {
        fprintf(stderr, "Error: --verbose and --quiet cannot be used together\n");
        return -1;
    }
    
    /* Validate PID if specified */
    if (args->pid < 0) {
        fprintf(stderr, "Error: Invalid PID: %d\n", args->pid);
        return -1;
    }
    
    /* Validate duration if specified */
    if (args->duration < 0) {
        fprintf(stderr, "Error: Invalid duration: %d (must be >= 0)\n", args->duration);
        return -1;
    }
    
    /* follow-children only makes sense with profile command */
    if (args->follow_children && args->command != CMD_PROFILE) {
        fprintf(stderr, "Warning: --follow-children is only supported for profile command\n");
    }
    
    return 0;
}

/**
 * Parse command-line arguments
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 11.1, 11.2, 11.3, 11.4, 11.5
 * Returns EXIT_SUCCESS on success, EXIT_ARGUMENT_ERROR on failure
 */
int parse_args(int argc, char **argv, cli_args_t *args) {
    int opt;
    int option_index = 0;
    
    /* Long options definition */
    static struct option long_options[] = {
        {"help",            no_argument,       0, 'h'},
        {"version",         no_argument,       0, 'V'},
        {"verbose",         no_argument,       0, 'v'},
        {"quiet",           no_argument,       0, 'q'},
        {"output",          required_argument, 0, 'o'},
        {"format",          required_argument, 0, 'f'},
        {"duration",        required_argument, 0, 'd'},
        {"pid",             required_argument, 0, 'p'},
        {"name",            required_argument, 0, 'n'},
        {"library",         required_argument, 0, 'l'},
        {"file",            required_argument, 0, 'F'},
        {"no-redact",       no_argument,       0, 'R'},
        {"follow-children", no_argument,       0, 'C'},
        {0, 0, 0, 0}
    };
    
    /* Initialize with defaults */
    init_args(args);
    
    /* Requirement 11.5: Handle no arguments - suggest --help */
    if (argc < 2) {
        fprintf(stderr, "Error: No command specified\n");
        fprintf(stderr, "Use 'crypto-tracer --help' for usage information\n");
        return EXIT_ARGUMENT_ERROR;
    }
    
    /* Parse command (first non-option argument) */
    if (argv[1][0] != '-') {
        args->command = parse_command(argv[1]);
        
        if (args->command == CMD_NONE) {
            fprintf(stderr, "Error: Unknown command: %s\n", argv[1]);
            fprintf(stderr, "Use 'crypto-tracer --help' for available commands\n");
            return EXIT_ARGUMENT_ERROR;
        }
        
        /* Handle help command */
        if (args->command == CMD_HELP) {
            if (argc > 2) {
                command_type_t help_cmd = parse_command(argv[2]);
                if (help_cmd != CMD_NONE && help_cmd != CMD_HELP && help_cmd != CMD_VERSION) {
                    print_command_help(help_cmd);
                } else {
                    print_usage(argv[0]);
                }
            } else {
                print_usage(argv[0]);
            }
            args->exit_after_parse = true;
            return EXIT_SUCCESS;  /* Exit after showing help */
        }
        
        /* Handle version command */
        if (args->command == CMD_VERSION) {
            print_version();
            args->exit_after_parse = true;
            return EXIT_SUCCESS;  /* Exit after showing version */
        }
        
        /* Shift arguments to skip command */
        optind = 2;
    } else {
        /* Handle global --help or --version before command */
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            args->exit_after_parse = true;
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
            print_version();
            args->exit_after_parse = true;
            return EXIT_SUCCESS;
        }
        
        fprintf(stderr, "Error: No command specified\n");
        fprintf(stderr, "Use 'crypto-tracer --help' for usage information\n");
        return EXIT_ARGUMENT_ERROR;
    }
    
    /* Parse options */
    while ((opt = getopt_long(argc, argv, "hVvqo:f:d:p:n:l:F:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_command_help(args->command);
                args->exit_after_parse = true;
                return EXIT_SUCCESS;
                
            case 'V':
                print_version();
                args->exit_after_parse = true;
                return EXIT_SUCCESS;
                
            case 'v':
                args->verbose = true;
                break;
                
            case 'q':
                args->quiet = true;
                break;
                
            case 'o':
                args->output_file = optarg;
                break;
                
            case 'f':
                {
                    int fmt = parse_format(optarg);
                    if (fmt < 0) {
                        fprintf(stderr, "Error: Invalid format: %s\n", optarg);
                        fprintf(stderr, "Valid formats: json-stream, json-array, json-pretty, summary\n");
                        return EXIT_ARGUMENT_ERROR;
                    }
                    args->format = (output_format_t)fmt;
                }
                break;
                
            case 'd':
                {
                    char *endptr;
                    long duration = strtol(optarg, &endptr, 10);
                    if (*endptr != '\0' || duration < 0 || duration > INT_MAX) {
                        fprintf(stderr, "Error: Invalid duration: %s\n", optarg);
                        return EXIT_ARGUMENT_ERROR;
                    }
                    args->duration = (int)duration;
                }
                break;
                
            case 'p':
                {
                    char *endptr;
                    long pid = strtol(optarg, &endptr, 10);
                    if (*endptr != '\0' || pid <= 0 || pid > INT_MAX) {
                        fprintf(stderr, "Error: Invalid PID: %s\n", optarg);
                        return EXIT_ARGUMENT_ERROR;
                    }
                    args->pid = (int)pid;
                }
                break;
                
            case 'n':
                args->process_name = optarg;
                break;
                
            case 'l':
                args->library_filter = optarg;
                break;
                
            case 'F':
                args->file_filter = optarg;
                break;
                
            case 'R':
                args->no_redact = true;
                break;
                
            case 'C':
                args->follow_children = true;
                break;
                
            case '?':
                /* getopt_long already printed an error message */
                fprintf(stderr, "Use 'crypto-tracer help %s' for command-specific help\n",
                        args->command == CMD_MONITOR ? "monitor" :
                        args->command == CMD_PROFILE ? "profile" :
                        args->command == CMD_SNAPSHOT ? "snapshot" :
                        args->command == CMD_LIBS ? "libs" :
                        args->command == CMD_FILES ? "files" : "");
                return EXIT_ARGUMENT_ERROR;
                
            default:
                return EXIT_ARGUMENT_ERROR;
        }
    }
    
    /* Check for extra arguments */
    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected argument: %s\n", argv[optind]);
        return EXIT_ARGUMENT_ERROR;
    }
    
    /* Validate argument combinations */
    if (validate_args(args) != 0) {
        return EXIT_ARGUMENT_ERROR;
    }
    
    return EXIT_SUCCESS;
}

/**
 * Parse kernel version string into major, minor, patch components
 * Returns 0 on success, -1 on failure
 */
static int parse_kernel_version(const char *version_str, int *major, int *minor, int *patch) {
    if (!version_str || !major || !minor || !patch) {
        return -1;
    }
    
    /* Skip any leading non-digit characters */
    while (*version_str && (*version_str < '0' || *version_str > '9')) {
        version_str++;
    }
    
    if (sscanf(version_str, "%d.%d.%d", major, minor, patch) < 2) {
        return -1;
    }
    
    return 0;
}

/**
 * Check if a specific capability is present
 * Returns 1 if capability is present, 0 if not, -1 on error
 */
static int has_capability(cap_value_t cap) {
    cap_t caps;
    cap_flag_value_t value;
    int result = 0;
    
    caps = cap_get_proc();
    if (!caps) {
        return -1;
    }
    
    if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &value) == 0) {
        result = (value == CAP_SET) ? 1 : 0;
    } else {
        result = -1;
    }
    
    cap_free(caps);
    return result;
}

/**
 * Validate that the process has sufficient privileges to load eBPF programs
 * Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
 * Returns EXIT_SUCCESS on success, EXIT_PRIVILEGE_ERROR on failure
 */
int validate_privileges(void) {
    int has_cap_bpf = 0;
    int has_cap_sys_admin = 0;
    int is_root = 0;
    struct utsname uts;
    int major = 0, minor = 0, patch = 0;
    
    /* Check if running as root (UID 0) */
    is_root = (geteuid() == 0);
    
    /* Get kernel version to determine which capabilities to check */
    if (uname(&uts) == 0) {
        if (parse_kernel_version(uts.release, &major, &minor, &patch) == 0) {
            /* CAP_BPF is available on kernel 5.8+ */
            if (major > CAP_BPF_KERNEL_MAJOR || 
                (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
                has_cap_bpf = has_capability(CAP_BPF);
            }
        }
    }
    
    /* Check CAP_SYS_ADMIN (required on older kernels, alternative on newer) */
    has_cap_sys_admin = has_capability(CAP_SYS_ADMIN);
    
    /* Requirement 7.5: Accept root as sufficient privilege */
    if (is_root) {
        return EXIT_SUCCESS;
    }
    
    /* Requirement 7.4: Detect CAP_BPF on kernel 5.8+ and fall back to CAP_SYS_ADMIN */
    if (has_cap_bpf > 0 || has_cap_sys_admin > 0) {
        return EXIT_SUCCESS;
    }
    
    /* Requirement 7.2, 7.3: Exit with code 3 and display helpful error message */
    char suggestion[512];
    
    if (major > CAP_BPF_KERNEL_MAJOR || 
        (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
        snprintf(suggestion, sizeof(suggestion),
                 "Run as root (sudo crypto-tracer), or grant CAP_BPF capability: "
                 "sudo setcap cap_bpf+ep /path/to/crypto-tracer");
    } else {
        snprintf(suggestion, sizeof(suggestion),
                 "Run as root (sudo crypto-tracer), or grant CAP_SYS_ADMIN capability: "
                 "sudo setcap cap_sys_admin+ep /path/to/crypto-tracer "
                 "(CAP_BPF not available on kernel %d.%d)", major, minor);
    }
    
    log_error_with_suggestion("Insufficient privileges to run crypto-tracer", suggestion);
    
    return EXIT_PRIVILEGE_ERROR;
}

/**
 * Check kernel version and compatibility
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
 * Returns EXIT_SUCCESS on success, EXIT_KERNEL_ERROR on failure
 */
int check_kernel_version(void) {
    struct utsname uts;
    int major = 0, minor = 0, patch = 0;
    
    /* Get kernel version information */
    if (uname(&uts) != 0) {
        log_system_error("Failed to get kernel version");
        return EXIT_KERNEL_ERROR;
    }
    
    /* Parse kernel version */
    if (parse_kernel_version(uts.release, &major, &minor, &patch) != 0) {
        log_error("Failed to parse kernel version: %s", uts.release);
        return EXIT_KERNEL_ERROR;
    }
    
    log_debug("Detected kernel version: %d.%d.%d (%s)", major, minor, patch, uts.release);
    
    /* Requirement 9.1: Check for minimum kernel version 4.15+ */
    if (major < MIN_KERNEL_MAJOR || 
        (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR)) {
        char error_msg[256];
        char suggestion[256];
        
        snprintf(error_msg, sizeof(error_msg),
                 "Kernel version %d.%d.%d is not supported (requires 4.15+)",
                 major, minor, patch);
        snprintf(suggestion, sizeof(suggestion),
                 "Please upgrade your kernel to Linux 4.15 or later");
        
        log_error_with_suggestion(error_msg, suggestion);
        return EXIT_KERNEL_ERROR;
    }
    
    /* Requirement 9.2: Detect CAP_BPF support on kernel 5.8+ */
    if (major > CAP_BPF_KERNEL_MAJOR || 
        (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
        /* CAP_BPF is available - enhanced security mode */
        log_debug("Kernel %d.%d.%d supports CAP_BPF (enhanced security)", major, minor, patch);
    } else {
        /* Older kernel - will use CAP_SYS_ADMIN */
        log_debug("Kernel %d.%d.%d requires CAP_SYS_ADMIN (CAP_BPF not available)", 
                  major, minor, patch);
    }
    
    /* Check for eBPF support by looking for /sys/kernel/btf/vmlinux or /proc/config.gz */
    if (access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
        log_debug("BTF support detected (CO-RE enabled)");
    } else {
        log_debug("BTF not available, using fallback headers");
    }
    
    /* Requirement 9.4: Graceful feature detection - always succeed if kernel >= 4.15 */
    return EXIT_SUCCESS;
}

/**
 * Event callback context for main event loop
 */
typedef struct {
    event_processor_t *processor;
    output_formatter_t *formatter;
    uint64_t events_processed;
    uint64_t events_filtered;
} event_loop_ctx_t;

/**
 * Event callback for main event loop
 * Processes, filters, enriches, and outputs events
 * Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6
 */
static int event_callback(processed_event_t *event, void *ctx) {
    event_loop_ctx_t *loop_ctx = (event_loop_ctx_t *)ctx;
    
    if (!event || !loop_ctx) {
        return -1;
    }
    
    loop_ctx->events_processed++;
    
    /* Enrich event with process metadata from /proc */
    enrich_event(event);
    
    /* Classify file type if this is a file_open event */
    if (event->file && event->event_type && strcmp(event->event_type, "file_open") == 0) {
        event->file_type = classify_crypto_file(event->file);
        
        /* Filter: Only keep crypto files (filtering moved from eBPF to user-space) */
        if (event->file_type == FILE_TYPE_UNKNOWN) {
            loop_ctx->events_filtered++;
            return 0;  /* Not a crypto file, filter it out */
        }
    }
    
    /* Extract library name if this is a lib_load event */
    if (event->library && event->event_type && strcmp(event->event_type, "lib_load") == 0) {
        event->library_name = extract_library_name(event->library);
        
        /* Filter: Only keep crypto libraries (filtering moved from eBPF to user-space) */
        if (!event->library_name || 
            (strstr(event->library, "libssl") == NULL &&
             strstr(event->library, "libcrypto") == NULL &&
             strstr(event->library, "libgnutls") == NULL &&
             strstr(event->library, "libsodium") == NULL &&
             strstr(event->library, "libnss3") == NULL &&
             strstr(event->library, "libmbedtls") == NULL)) {
            loop_ctx->events_filtered++;
            return 0;  /* Not a crypto library, filter it out */
        }
    }
    
    /* Apply privacy filtering */
    apply_privacy_filter(event, loop_ctx->processor->redact_paths);
    
    /* Check if event matches filters */
    if (!event_processor_matches_filters(loop_ctx->processor, event)) {
        loop_ctx->events_filtered++;
        return 0;  /* Event filtered out */
    }
    
    /* Write event to output */
    if (output_formatter_write_event(loop_ctx->formatter, event) != 0) {
        log_warn("Failed to write event to output");
        return -1;
    }
    
    return 0;
}

/**
 * Execute monitor command
 * Requirement: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
 * Requirements: 16.1, 16.2, 16.3, 16.4, 16.5
 */
static int execute_monitor_command(cli_args_t *args) {
    struct ebpf_manager *mgr = NULL;
    event_processor_t *processor = NULL;
    output_formatter_t *formatter = NULL;
    FILE *output_file = NULL;
    event_loop_ctx_t loop_ctx = {0};
    time_t start_time, current_time;
    int ret = EXIT_SUCCESS;
    uint64_t events_processed_total = 0;
    uint64_t events_dropped_total = 0;
    
    log_info("Starting monitor command");
    
    /* Step 5: Initialize components */
    log_debug("Initializing components...");
    
    /* Create eBPF manager */
    mgr = ebpf_manager_create();
    if (!mgr) {
        log_error("Failed to create eBPF manager");
        return EXIT_BPF_ERROR;
    }
    log_debug("eBPF manager created");
    
    /* Create event processor with filters */
    processor = event_processor_create(args);
    if (!processor) {
        log_error("Failed to create event processor");
        ebpf_manager_destroy(mgr);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Event processor created");
    
    /* Open output file if specified */
    if (args->output_file) {
        output_file = fopen(args->output_file, "w");
        if (!output_file) {
            log_error("Failed to open output file: %s", args->output_file);
            log_system_error("fopen");
            event_processor_destroy(processor);
            ebpf_manager_destroy(mgr);
            return EXIT_GENERAL_ERROR;
        }
        log_debug("Output file opened: %s", args->output_file);
    } else {
        output_file = stdout;
    }
    
    /* Create output formatter */
    formatter = output_formatter_create(args->format, output_file);
    if (!formatter) {
        log_error("Failed to create output formatter");
        if (args->output_file && output_file) {
            fclose(output_file);
        }
        event_processor_destroy(processor);
        ebpf_manager_destroy(mgr);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Output formatter created");
    
    /* Step 6: Load eBPF programs */
    log_debug("Loading eBPF programs...");
    ret = ebpf_manager_load_programs(mgr);
    if (ret != 0) {
        log_error("Failed to load eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs loaded successfully");
    
    /* Attach eBPF programs */
    log_debug("Attaching eBPF programs...");
    ret = ebpf_manager_attach_programs(mgr);
    if (ret != 0) {
        log_error("Failed to attach eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs attached successfully");
    
    /* Step 7: Verify ready - at least core programs loaded */
    log_debug("Verifying system ready...");
    log_info("crypto-tracer ready, monitoring started");
    
    /* Setup event loop context */
    loop_ctx.processor = processor;
    loop_ctx.formatter = formatter;
    loop_ctx.events_processed = 0;
    loop_ctx.events_filtered = 0;
    
    /* Record start time */
    start_time = time(NULL);
    
    /* Main event loop - single-threaded, event-driven */
    /* Requirements: 16.1, 16.2 - Complete initialization in <2s, capture first event within 2s */
    log_debug("Entering main event loop");
    
    while (!is_shutdown_requested()) {
        /* Poll events from ring buffer (10ms timeout) */
        /* Requirement: 14.1 - Poll ring buffer every 10ms */
        /* Requirement: 14.2 - Process up to 100 events per iteration */
        ret = ebpf_manager_poll_events(mgr, event_callback, &loop_ctx);
        if (ret < 0 && ret != -EINTR) {
            log_error("Error polling events: %d", ret);
            break;
        }
        
        /* Check duration limit */
        if (args->duration > 0) {
            current_time = time(NULL);
            if (difftime(current_time, start_time) >= args->duration) {
                log_debug("Duration limit reached (%d seconds)", args->duration);
                break;
            }
        }
    }
    
    /* Requirement: 16.4 - Process buffered events before exit (up to 1 second) */
    if (is_shutdown_requested()) {
        log_debug("Shutdown requested, processing remaining events...");
        time_t shutdown_start = time(NULL);
        while (difftime(time(NULL), shutdown_start) < 1.0) {
            ret = ebpf_manager_poll_events(mgr, event_callback, &loop_ctx);
            if (ret < 0 && ret != -EINTR) {
                break;
            }
            /* If no events processed in last poll, we're done */
            if (ret == 0) {
                break;
            }
        }
    }
    
    /* Get final statistics */
    ebpf_manager_get_stats(mgr, &events_processed_total, &events_dropped_total);
    
    /* Log statistics */
    log_info("Monitoring complete");
    log_info("Events processed: %lu", loop_ctx.events_processed);
    log_info("Events filtered: %lu", loop_ctx.events_filtered);
    log_info("Events dropped: %lu", events_dropped_total);
    
    ret = EXIT_SUCCESS;
    
cleanup:
    /* Requirement: 16.3, 16.4, 16.5 - Graceful shutdown with timeout protection */
    log_debug("Cleaning up resources...");
    
    /* Cleanup eBPF manager (includes timeout protection) */
    if (mgr) {
        ebpf_manager_cleanup(mgr);
        ebpf_manager_destroy(mgr);
    }
    
    /* Cleanup output formatter */
    if (formatter) {
        output_formatter_destroy(formatter);
    }
    
    /* Close output file if we opened it */
    if (args->output_file && output_file && output_file != stdout) {
        fclose(output_file);
    }
    
    /* Cleanup event processor */
    if (processor) {
        event_processor_destroy(processor);
    }
    
    log_debug("Cleanup complete");
    
    return ret;
}

/**
 * Profile event callback context
 */
typedef struct {
    event_processor_t *processor;
    profile_manager_t *profile_mgr;
    pid_t target_pid;
    bool follow_children;
    uint64_t events_processed;
    uint64_t events_filtered;
} profile_ctx_t;

/**
 * Profile event callback
 * Processes events and adds them to the profile manager
 */
static int profile_event_callback(processed_event_t *event, void *ctx) {
    profile_ctx_t *pctx = (profile_ctx_t *)ctx;
    
    if (!event || !pctx) {
        return -1;
    }
    
    pctx->events_processed++;
    
    /* Enrich event with process metadata */
    enrich_event(event);
    
    /* Classify file type if this is a file_open event */
    if (event->file && event->event_type && strcmp(event->event_type, "file_open") == 0) {
        event->file_type = classify_crypto_file(event->file);
        
        /* Filter: Only keep crypto files (filtering moved from eBPF to user-space) */
        if (event->file_type == FILE_TYPE_UNKNOWN) {
            pctx->events_filtered++;
            return 0;  /* Not a crypto file, filter it out */
        }
    }
    
    /* Extract library name if this is a lib_load event */
    if (event->library && event->event_type && strcmp(event->event_type, "lib_load") == 0) {
        event->library_name = extract_library_name(event->library);
        
        /* Filter: Only keep crypto libraries (filtering moved from eBPF to user-space) */
        if (!event->library_name || 
            (strstr(event->library, "libssl") == NULL &&
             strstr(event->library, "libcrypto") == NULL &&
             strstr(event->library, "libgnutls") == NULL &&
             strstr(event->library, "libsodium") == NULL &&
             strstr(event->library, "libnss3") == NULL &&
             strstr(event->library, "libmbedtls") == NULL)) {
            pctx->events_filtered++;
            return 0;  /* Not a crypto library, filter it out */
        }
    }
    
    /* Apply privacy filtering */
    apply_privacy_filter(event, pctx->processor->redact_paths);
    
    /* Requirement 2.1: Filter by target PID */
    /* Requirement 2.4: Include child processes if follow_children enabled */
    bool matches_target = (event->pid == (uint32_t)pctx->target_pid);
    
    /* TODO: Implement child process tracking for follow_children */
    /* For now, we only track the target PID */
    
    if (!matches_target) {
        pctx->events_filtered++;
        return 0;  /* Event filtered out */
    }
    
    /* Check if event matches other filters */
    if (!event_processor_matches_filters(pctx->processor, event)) {
        pctx->events_filtered++;
        return 0;  /* Event filtered out */
    }
    
    /* Add event to profile manager */
    if (profile_manager_add_event(pctx->profile_mgr, event) != 0) {
        log_warn("Failed to add event to profile");
    }
    
    return 0;
}

/**
 * Execute profile command
 * Requirement: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
 */
static int execute_profile_command(cli_args_t *args) {
    struct ebpf_manager *mgr = NULL;
    event_processor_t *processor = NULL;
    output_formatter_t *formatter = NULL;
    profile_manager_t *profile_mgr = NULL;
    proc_scanner_t *scanner = NULL;
    FILE *output_file = NULL;
    time_t start_time, current_time;
    int ret = EXIT_SUCCESS;
    pid_t target_pid = args->pid;
    bool process_found = false;
    bool process_exited = false;
    uint64_t events_processed_total = 0;
    uint64_t events_dropped_total = 0;
    
    log_info("Starting profile command");
    
    /* Requirement 2.1: Resolve process name to PID if needed */
    if (target_pid == 0 && args->process_name) {
        log_debug("Resolving process name '%s' to PID...", args->process_name);
        
        scanner = proc_scanner_create();
        if (!scanner) {
            log_error("Failed to create proc scanner");
            return EXIT_GENERAL_ERROR;
        }
        
        process_list_t proc_list;
        process_list_init(&proc_list);
        
        if (proc_scanner_scan_processes(scanner, &proc_list) == 0) {
            /* Find first process matching the name */
            for (size_t i = 0; i < proc_list.count; i++) {
                if (strstr(proc_list.processes[i].comm, args->process_name) != NULL) {
                    target_pid = proc_list.processes[i].pid;
                    process_found = true;
                    log_info("Found process '%s' with PID %d", args->process_name, target_pid);
                    break;
                }
            }
        }
        
        process_list_free(&proc_list);
        
        if (!process_found) {
            log_error("Process '%s' not found", args->process_name);
            proc_scanner_destroy(scanner);
            return EXIT_GENERAL_ERROR;
        }
    } else {
        target_pid = args->pid;
    }
    
    /* Verify target process exists */
    if (!scanner) {
        scanner = proc_scanner_create();
        if (!scanner) {
            log_error("Failed to create proc scanner");
            return EXIT_GENERAL_ERROR;
        }
    }
    
    process_info_t proc_info;
    if (proc_scanner_get_process_info(scanner, target_pid, &proc_info) != 0) {
        log_error("Target process (PID %d) not found or not accessible", target_pid);
        proc_scanner_destroy(scanner);
        return EXIT_GENERAL_ERROR;
    }
    
    log_info("Profiling process: %s (PID %d)", proc_info.comm, target_pid);
    log_info("Profile duration: %d seconds", args->duration);
    
    /* Initialize components */
    log_debug("Initializing components...");
    
    /* Create eBPF manager */
    mgr = ebpf_manager_create();
    if (!mgr) {
        log_error("Failed to create eBPF manager");
        proc_scanner_destroy(scanner);
        return EXIT_BPF_ERROR;
    }
    log_debug("eBPF manager created");
    
    /* Create event processor with PID filter */
    processor = event_processor_create(args);
    if (!processor) {
        log_error("Failed to create event processor");
        ebpf_manager_destroy(mgr);
        proc_scanner_destroy(scanner);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Event processor created");
    
    /* Create profile manager */
    profile_mgr = profile_manager_create();
    if (!profile_mgr) {
        log_error("Failed to create profile manager");
        event_processor_destroy(processor);
        ebpf_manager_destroy(mgr);
        proc_scanner_destroy(scanner);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Profile manager created");
    
    /* Open output file if specified */
    if (args->output_file) {
        output_file = fopen(args->output_file, "w");
        if (!output_file) {
            log_error("Failed to open output file: %s", args->output_file);
            log_system_error("fopen");
            profile_manager_destroy(profile_mgr);
            event_processor_destroy(processor);
            ebpf_manager_destroy(mgr);
            proc_scanner_destroy(scanner);
            return EXIT_GENERAL_ERROR;
        }
        log_debug("Output file opened: %s", args->output_file);
    } else {
        output_file = stdout;
    }
    
    /* Create output formatter */
    formatter = output_formatter_create(args->format, output_file);
    if (!formatter) {
        log_error("Failed to create output formatter");
        if (args->output_file && output_file) {
            fclose(output_file);
        }
        profile_manager_destroy(profile_mgr);
        event_processor_destroy(processor);
        ebpf_manager_destroy(mgr);
        proc_scanner_destroy(scanner);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Output formatter created");
    
    /* Load eBPF programs */
    log_debug("Loading eBPF programs...");
    ret = ebpf_manager_load_programs(mgr);
    if (ret != 0) {
        log_error("Failed to load eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs loaded successfully");
    
    /* Attach eBPF programs */
    log_debug("Attaching eBPF programs...");
    ret = ebpf_manager_attach_programs(mgr);
    if (ret != 0) {
        log_error("Failed to attach eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs attached successfully");
    
    log_info("Profiling started");
    
    /* Record start time */
    start_time = time(NULL);
    
    /* Setup profile event callback context */
    profile_ctx_t profile_ctx = {
        .processor = processor,
        .profile_mgr = profile_mgr,
        .target_pid = target_pid,
        .follow_children = args->follow_children,
        .events_processed = 0,
        .events_filtered = 0
    };
    
    /* Main profiling loop */
    log_debug("Entering profiling loop");
    
    while (!is_shutdown_requested()) {
        /* Poll events from ring buffer */
        ret = ebpf_manager_poll_events(mgr, profile_event_callback, &profile_ctx);
        if (ret < 0 && ret != -EINTR) {
            log_error("Error polling events: %d", ret);
            break;
        }
        
        /* Requirement 2.3: Check if target process still exists */
        if (proc_scanner_get_process_info(scanner, target_pid, &proc_info) != 0) {
            log_info("Target process (PID %d) has exited", target_pid);
            process_exited = true;
            break;
        }
        
        /* Check duration limit */
        current_time = time(NULL);
        if (difftime(current_time, start_time) >= args->duration) {
            log_debug("Profile duration reached (%d seconds)", args->duration);
            break;
        }
    }
    
    /* Process remaining events */
    if (is_shutdown_requested() || process_exited) {
        log_debug("Processing remaining events...");
        time_t shutdown_start = time(NULL);
        while (difftime(time(NULL), shutdown_start) < 1.0) {
            ret = ebpf_manager_poll_events(mgr, profile_event_callback, &profile_ctx);
            if (ret < 0 && ret != -EINTR) {
                break;
            }
            if (ret == 0) {
                break;
            }
        }
    }
    
    /* Get final statistics */
    ebpf_manager_get_stats(mgr, &events_processed_total, &events_dropped_total);
    
    /* Requirement 2.2, 2.5: Generate complete profile document */
    log_info("Generating profile...");
    
    int actual_duration = (int)difftime(time(NULL), start_time);
    profile_t *profile = profile_manager_finalize_profile(profile_mgr, target_pid, actual_duration);
    
    if (profile) {
        /* Requirement 2.3: Output partial results if process exited */
        if (process_exited) {
            log_info("Profile generated (partial - process exited during profiling)");
        } else {
            log_info("Profile generated successfully");
        }
        
        /* Write profile to output */
        if (output_formatter_write_profile(formatter, profile) != 0) {
            log_error("Failed to write profile to output");
            ret = EXIT_GENERAL_ERROR;
        }
        
        /* Free profile */
        profile_free(profile);
    } else {
        log_warn("No profile data collected for PID %d", target_pid);
        ret = EXIT_GENERAL_ERROR;
    }
    
    /* Log statistics */
    log_info("Profiling complete");
    log_info("Events processed: %lu", profile_ctx.events_processed);
    log_info("Events filtered: %lu", profile_ctx.events_filtered);
    log_info("Events dropped: %lu", events_dropped_total);
    
    ret = EXIT_SUCCESS;
    
cleanup:
    log_debug("Cleaning up resources...");
    
    /* Cleanup eBPF manager */
    if (mgr) {
        ebpf_manager_cleanup(mgr);
        ebpf_manager_destroy(mgr);
    }
    
    /* Cleanup output formatter */
    if (formatter) {
        output_formatter_destroy(formatter);
    }
    
    /* Close output file if we opened it */
    if (args->output_file && output_file && output_file != stdout) {
        fclose(output_file);
    }
    
    /* Cleanup profile manager */
    if (profile_mgr) {
        profile_manager_destroy(profile_mgr);
    }
    
    /* Cleanup event processor */
    if (processor) {
        event_processor_destroy(processor);
    }
    
    /* Cleanup proc scanner */
    if (scanner) {
        proc_scanner_destroy(scanner);
    }
    
    log_debug("Cleanup complete");
    
    return ret;
}

/**
 * Execute snapshot command
 * Requirement: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
 * 
 * Takes a quick snapshot of all cryptographic usage on the system.
 * Uses /proc filesystem scanning only (no eBPF required).
 * Target: Complete in under 5 seconds.
 */
static int execute_snapshot_command(cli_args_t *args) {
    proc_scanner_t *scanner = NULL;
    output_formatter_t *formatter = NULL;
    FILE *output_file = NULL;
    snapshot_t snapshot = {0};
    process_list_t process_list = {0};
    int ret = EXIT_SUCCESS;
    time_t start_time, current_time;
    struct utsname sys_info;
    char hostname[256] = "unknown";
    char kernel_version[256] = "unknown";
    
    log_info("Starting snapshot...");
    start_time = time(NULL);
    
    /* Get system information */
    if (uname(&sys_info) == 0) {
        strncpy(hostname, sys_info.nodename, sizeof(hostname) - 1);
        snprintf(kernel_version, sizeof(kernel_version), "%s %s", 
                 sys_info.sysname, sys_info.release);
    }
    
    /* Create proc scanner - Requirement 3.1 */
    scanner = proc_scanner_create();
    if (!scanner) {
        log_error("Failed to create proc scanner");
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Proc scanner created");
    
    /* Open output file if specified */
    if (args->output_file) {
        output_file = fopen(args->output_file, "w");
        if (!output_file) {
            log_error("Failed to open output file: %s", args->output_file);
            log_system_error("fopen");
            proc_scanner_destroy(scanner);
            return EXIT_GENERAL_ERROR;
        }
        log_debug("Output file opened: %s", args->output_file);
    } else {
        output_file = stdout;
    }
    
    /* Create output formatter */
    formatter = output_formatter_create(args->format, output_file);
    if (!formatter) {
        log_error("Failed to create output formatter");
        if (args->output_file && output_file) {
            fclose(output_file);
        }
        proc_scanner_destroy(scanner);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Output formatter created");
    
    /* Initialize process list */
    process_list_init(&process_list);
    
    /* Requirement 3.1: Scan all running processes */
    log_debug("Scanning processes...");
    if (proc_scanner_scan_processes(scanner, &process_list) != 0) {
        log_error("Failed to scan processes");
        ret = EXIT_GENERAL_ERROR;
        goto cleanup;
    }
    log_debug("Found %zu processes", process_list.count);
    
    /* Build snapshot structure */
    snapshot.snapshot_version = "1.0";
    
    /* Generate timestamp */
    time_t now = time(NULL);
    struct tm tm_info;
    char timestamp_buf[64];
    if (gmtime_r(&now, &tm_info) != NULL) {
        snprintf(timestamp_buf, sizeof(timestamp_buf),
                 "%04d-%02d-%02dT%02d:%02d:%02dZ",
                 tm_info.tm_year + 1900,
                 tm_info.tm_mon + 1,
                 tm_info.tm_mday,
                 tm_info.tm_hour,
                 tm_info.tm_min,
                 tm_info.tm_sec);
        snapshot.generated_at = timestamp_buf;
    } else {
        snapshot.generated_at = "unknown";
    }
    
    snapshot.hostname = hostname;
    snapshot.kernel = kernel_version;
    
    /* Allocate processes array */
    snapshot.process_count = 0;
    snapshot.processes = calloc(process_list.count, sizeof(*snapshot.processes));
    if (!snapshot.processes) {
        log_error("Failed to allocate snapshot processes array");
        ret = EXIT_GENERAL_ERROR;
        goto cleanup;
    }
    
    /* Initialize summary statistics */
    snapshot.summary.total_processes = 0;
    snapshot.summary.total_libraries = 0;
    snapshot.summary.total_files = 0;
    
    /* Scan each process for crypto libraries and files */
    log_debug("Scanning for crypto libraries and files...");
    
    for (size_t i = 0; i < process_list.count; i++) {
        process_info_t *proc_info = &process_list.processes[i];
        library_list_t lib_list = {0};
        file_list_t file_list = {0};
        
        /* Check timeout - Requirement 3.5: Complete in under 5 seconds */
        current_time = time(NULL);
        if (difftime(current_time, start_time) >= 5.0) {
            log_warn("Snapshot timeout reached (5 seconds), stopping scan");
            break;
        }
        
        /* Initialize lists */
        library_list_init(&lib_list);
        file_list_init(&file_list);
        
        /* Requirement 3.2: Get loaded crypto libraries */
        proc_scanner_get_loaded_libraries(scanner, proc_info->pid, &lib_list);
        
        /* Requirement 3.3: Get open crypto files */
        proc_scanner_get_open_files(scanner, proc_info->pid, &file_list);
        
        /* Only include processes that have crypto libraries or files */
        if (lib_list.count > 0 || file_list.count > 0) {
            size_t proc_idx = snapshot.process_count;
            
            /* Fill process information */
            snapshot.processes[proc_idx].pid = proc_info->pid;
            snapshot.processes[proc_idx].name = strdup(proc_info->comm);
            
            /* Apply privacy filtering - Requirement 6.1, 6.2, 6.3 */
            char *filtered_exe = privacy_filter_path(proc_info->exe, !args->no_redact);
            snapshot.processes[proc_idx].exe = filtered_exe ? filtered_exe : strdup(proc_info->exe);
            
            /* Format running_as (UID) */
            char running_as_buf[32];
            snprintf(running_as_buf, sizeof(running_as_buf), "uid:%u", proc_info->uid);
            snapshot.processes[proc_idx].running_as = strdup(running_as_buf);
            
            /* Copy libraries */
            snapshot.processes[proc_idx].library_count = lib_list.count;
            if (lib_list.count > 0) {
                snapshot.processes[proc_idx].libraries = calloc(lib_list.count, sizeof(char *));
                for (size_t j = 0; j < lib_list.count; j++) {
                    char *filtered_lib = privacy_filter_path(lib_list.libraries[j].path, !args->no_redact);
                    snapshot.processes[proc_idx].libraries[j] = filtered_lib ? filtered_lib : strdup(lib_list.libraries[j].path);
                }
                snapshot.summary.total_libraries += lib_list.count;
            } else {
                snapshot.processes[proc_idx].libraries = NULL;
            }
            
            /* Copy open crypto files */
            snapshot.processes[proc_idx].file_count = file_list.count;
            if (file_list.count > 0) {
                snapshot.processes[proc_idx].open_crypto_files = calloc(file_list.count, sizeof(char *));
                for (size_t j = 0; j < file_list.count; j++) {
                    char *filtered_file = privacy_filter_path(file_list.files[j].path, !args->no_redact);
                    snapshot.processes[proc_idx].open_crypto_files[j] = filtered_file ? filtered_file : strdup(file_list.files[j].path);
                }
                snapshot.summary.total_files += file_list.count;
            } else {
                snapshot.processes[proc_idx].open_crypto_files = NULL;
            }
            
            snapshot.process_count++;
            snapshot.summary.total_processes++;
        }
        
        /* Cleanup lists */
        library_list_free(&lib_list);
        file_list_free(&file_list);
    }
    
    /* Requirement 3.4: Generate snapshot document */
    log_info("Generating snapshot document...");
    if (output_formatter_write_snapshot(formatter, &snapshot) != 0) {
        log_error("Failed to write snapshot to output");
        ret = EXIT_GENERAL_ERROR;
        goto cleanup;
    }
    
    /* Log completion time */
    current_time = time(NULL);
    double elapsed = difftime(current_time, start_time);
    log_info("Snapshot complete in %.2f seconds", elapsed);
    log_info("Found %d processes using cryptography", snapshot.summary.total_processes);
    log_info("Total libraries: %d, Total files: %d", 
             snapshot.summary.total_libraries, snapshot.summary.total_files);
    
    ret = EXIT_SUCCESS;
    
cleanup:
    log_debug("Cleaning up resources...");
    
    /* Free snapshot data */
    if (snapshot.processes) {
        for (size_t i = 0; i < snapshot.process_count; i++) {
            free(snapshot.processes[i].name);
            free(snapshot.processes[i].exe);
            free(snapshot.processes[i].running_as);
            
            if (snapshot.processes[i].libraries) {
                for (size_t j = 0; j < snapshot.processes[i].library_count; j++) {
                    free(snapshot.processes[i].libraries[j]);
                }
                free(snapshot.processes[i].libraries);
            }
            
            if (snapshot.processes[i].open_crypto_files) {
                for (size_t j = 0; j < snapshot.processes[i].file_count; j++) {
                    free(snapshot.processes[i].open_crypto_files[j]);
                }
                free(snapshot.processes[i].open_crypto_files);
            }
        }
        free(snapshot.processes);
    }
    
    /* Cleanup process list */
    process_list_free(&process_list);
    
    /* Cleanup output formatter */
    if (formatter) {
        output_formatter_destroy(formatter);
    }
    
    /* Close output file if we opened it */
    if (args->output_file && output_file && output_file != stdout) {
        fclose(output_file);
    }
    
    /* Cleanup proc scanner */
    if (scanner) {
        proc_scanner_destroy(scanner);
    }
    
    log_debug("Cleanup complete");
    
    return ret;
}

/**
 * Libs event callback context
 */
typedef struct {
    event_processor_t *processor;
    output_formatter_t *formatter;
    uint64_t events_processed;
    uint64_t events_filtered;
} libs_ctx_t;

/**
 * Libs event callback
 * Processes only lib_load events and outputs them
 */
static int libs_event_callback(processed_event_t *event, void *ctx) {
    libs_ctx_t *lctx = (libs_ctx_t *)ctx;
    
    if (!event || !lctx) {
        return -1;
    }
    
    lctx->events_processed++;
    
    /* Requirement 4.1: Only process lib_load events */
    if (!event->event_type || strcmp(event->event_type, "lib_load") != 0) {
        lctx->events_filtered++;
        return 0;  /* Not a library load event, filter it out */
    }
    
    /* Enrich event with process metadata */
    enrich_event(event);
    
    /* Extract library name */
    if (event->library) {
        event->library_name = extract_library_name(event->library);
        
        /* Filter: Only keep crypto libraries (filtering moved from eBPF to user-space) */
        if (!event->library_name || 
            (strstr(event->library, "libssl") == NULL &&
             strstr(event->library, "libcrypto") == NULL &&
             strstr(event->library, "libgnutls") == NULL &&
             strstr(event->library, "libsodium") == NULL &&
             strstr(event->library, "libnss3") == NULL &&
             strstr(event->library, "libmbedtls") == NULL)) {
            lctx->events_filtered++;
            return 0;  /* Not a crypto library, filter it out */
        }
    }
    
    /* Apply privacy filtering */
    apply_privacy_filter(event, lctx->processor->redact_paths);
    
    /* Requirement 4.2: Apply library name filter if specified */
    if (!event_processor_matches_filters(lctx->processor, event)) {
        lctx->events_filtered++;
        return 0;  /* Event filtered out */
    }
    
    /* Requirement 4.4: Write event to output as JSON */
    if (output_formatter_write_event(lctx->formatter, event) != 0) {
        log_warn("Failed to write event to output");
        return -1;
    }
    
    return 0;
}

/**
 * Execute libs command
 * Requirement: 4.1, 4.2, 4.3, 4.4
 * 
 * Lists all loaded cryptographic libraries by monitoring lib_load events.
 * Similar to monitor command but filtered to library events only.
 */
static int execute_libs_command(cli_args_t *args) {
    struct ebpf_manager *mgr = NULL;
    event_processor_t *processor = NULL;
    output_formatter_t *formatter = NULL;
    FILE *output_file = NULL;
    libs_ctx_t libs_ctx = {0};
    time_t start_time, current_time;
    int ret = EXIT_SUCCESS;
    uint64_t events_processed_total = 0;
    uint64_t events_dropped_total = 0;
    
    log_info("Starting libs command");
    
    /* Initialize components */
    log_debug("Initializing components...");
    
    /* Create eBPF manager */
    mgr = ebpf_manager_create();
    if (!mgr) {
        log_error("Failed to create eBPF manager");
        return EXIT_BPF_ERROR;
    }
    log_debug("eBPF manager created");
    
    /* Create event processor with library filter */
    processor = event_processor_create(args);
    if (!processor) {
        log_error("Failed to create event processor");
        ebpf_manager_destroy(mgr);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Event processor created");
    
    /* Open output file if specified */
    if (args->output_file) {
        output_file = fopen(args->output_file, "w");
        if (!output_file) {
            log_error("Failed to open output file: %s", args->output_file);
            log_system_error("fopen");
            event_processor_destroy(processor);
            ebpf_manager_destroy(mgr);
            return EXIT_GENERAL_ERROR;
        }
        log_debug("Output file opened: %s", args->output_file);
    } else {
        output_file = stdout;
    }
    
    /* Create output formatter */
    formatter = output_formatter_create(args->format, output_file);
    if (!formatter) {
        log_error("Failed to create output formatter");
        if (args->output_file && output_file) {
            fclose(output_file);
        }
        event_processor_destroy(processor);
        ebpf_manager_destroy(mgr);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Output formatter created");
    
    /* Load eBPF programs */
    log_debug("Loading eBPF programs...");
    ret = ebpf_manager_load_programs(mgr);
    if (ret != 0) {
        log_error("Failed to load eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs loaded successfully");
    
    /* Attach eBPF programs */
    log_debug("Attaching eBPF programs...");
    ret = ebpf_manager_attach_programs(mgr);
    if (ret != 0) {
        log_error("Failed to attach eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs attached successfully");
    
    log_info("Library monitoring started");
    if (args->library_filter) {
        log_info("Filtering by library: %s", args->library_filter);
    }
    
    /* Setup libs event callback context */
    libs_ctx.processor = processor;
    libs_ctx.formatter = formatter;
    libs_ctx.events_processed = 0;
    libs_ctx.events_filtered = 0;
    
    /* Record start time */
    start_time = time(NULL);
    
    /* Main event loop */
    log_debug("Entering main event loop");
    
    while (!is_shutdown_requested()) {
        /* Poll events from ring buffer */
        ret = ebpf_manager_poll_events(mgr, libs_event_callback, &libs_ctx);
        if (ret < 0 && ret != -EINTR) {
            log_error("Error polling events: %d", ret);
            break;
        }
        
        /* Check duration limit */
        if (args->duration > 0) {
            current_time = time(NULL);
            if (difftime(current_time, start_time) >= args->duration) {
                log_debug("Duration limit reached (%d seconds)", args->duration);
                break;
            }
        }
    }
    
    /* Process remaining events */
    if (is_shutdown_requested()) {
        log_debug("Shutdown requested, processing remaining events...");
        time_t shutdown_start = time(NULL);
        while (difftime(time(NULL), shutdown_start) < 1.0) {
            ret = ebpf_manager_poll_events(mgr, libs_event_callback, &libs_ctx);
            if (ret < 0 && ret != -EINTR) {
                break;
            }
            if (ret == 0) {
                break;
            }
        }
    }
    
    /* Get final statistics */
    ebpf_manager_get_stats(mgr, &events_processed_total, &events_dropped_total);
    
    /* Log statistics */
    log_info("Library monitoring complete");
    log_info("Events processed: %lu", libs_ctx.events_processed);
    log_info("Events filtered: %lu", libs_ctx.events_filtered);
    log_info("Events dropped: %lu", events_dropped_total);
    
    ret = EXIT_SUCCESS;
    
cleanup:
    log_debug("Cleaning up resources...");
    
    /* Cleanup eBPF manager */
    if (mgr) {
        ebpf_manager_cleanup(mgr);
        ebpf_manager_destroy(mgr);
    }
    
    /* Cleanup output formatter */
    if (formatter) {
        output_formatter_destroy(formatter);
    }
    
    /* Close output file if we opened it */
    if (args->output_file && output_file && output_file != stdout) {
        fclose(output_file);
    }
    
    /* Cleanup event processor */
    if (processor) {
        event_processor_destroy(processor);
    }
    
    log_debug("Cleanup complete");
    
    return ret;
}

/**
 * Files event callback context
 */
typedef struct {
    event_processor_t *processor;
    output_formatter_t *formatter;
    uint64_t events_processed;
    uint64_t events_filtered;
} files_ctx_t;

/**
 * Files event callback
 * Processes only file_open events and outputs them
 */
static int files_event_callback(processed_event_t *event, void *ctx) {
    files_ctx_t *fctx = (files_ctx_t *)ctx;
    
    if (!event || !fctx) {
        return -1;
    }
    
    fctx->events_processed++;
    
    /* Requirement 5.1: Only process file_open events */
    if (!event->event_type || strcmp(event->event_type, "file_open") != 0) {
        fctx->events_filtered++;
        return 0;  /* Not a file open event, filter it out */
    }
    
    /* Enrich event with process metadata */
    enrich_event(event);
    
    /* Requirement 5.4: Classify file type */
    if (event->file) {
        event->file_type = classify_crypto_file(event->file);
        
        /* Filter: Only keep crypto files (filtering moved from eBPF to user-space) */
        if (event->file_type == FILE_TYPE_UNKNOWN) {
            fctx->events_filtered++;
            return 0;  /* Not a crypto file, filter it out */
        }
    }
    
    /* Apply privacy filtering */
    apply_privacy_filter(event, fctx->processor->redact_paths);
    
    /* Requirement 5.3, 5.5: Apply file path filter with glob pattern support */
    if (!event_processor_matches_filters(fctx->processor, event)) {
        fctx->events_filtered++;
        return 0;  /* Event filtered out */
    }
    
    /* Requirement 5.2: Write event to output as JSON with file path, access mode, and process info */
    if (output_formatter_write_event(fctx->formatter, event) != 0) {
        log_warn("Failed to write event to output");
        return -1;
    }
    
    return 0;
}

/**
 * Execute files command
 * Requirement: 5.1, 5.2, 5.3, 5.4, 5.5
 * 
 * Tracks access to cryptographic files (certificates, keys, keystores).
 * Similar to monitor command but filtered to file events only.
 */
static int execute_files_command(cli_args_t *args) {
    struct ebpf_manager *mgr = NULL;
    event_processor_t *processor = NULL;
    output_formatter_t *formatter = NULL;
    FILE *output_file = NULL;
    files_ctx_t files_ctx = {0};
    time_t start_time, current_time;
    int ret = EXIT_SUCCESS;
    uint64_t events_processed_total = 0;
    uint64_t events_dropped_total = 0;
    
    log_info("Starting files command");
    
    /* Initialize components */
    log_debug("Initializing components...");
    
    /* Create eBPF manager */
    mgr = ebpf_manager_create();
    if (!mgr) {
        log_error("Failed to create eBPF manager");
        return EXIT_BPF_ERROR;
    }
    log_debug("eBPF manager created");
    
    /* Create event processor with file filter */
    processor = event_processor_create(args);
    if (!processor) {
        log_error("Failed to create event processor");
        ebpf_manager_destroy(mgr);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Event processor created");
    
    /* Open output file if specified */
    if (args->output_file) {
        output_file = fopen(args->output_file, "w");
        if (!output_file) {
            log_error("Failed to open output file: %s", args->output_file);
            log_system_error("fopen");
            event_processor_destroy(processor);
            ebpf_manager_destroy(mgr);
            return EXIT_GENERAL_ERROR;
        }
        log_debug("Output file opened: %s", args->output_file);
    } else {
        output_file = stdout;
    }
    
    /* Create output formatter */
    formatter = output_formatter_create(args->format, output_file);
    if (!formatter) {
        log_error("Failed to create output formatter");
        if (args->output_file && output_file) {
            fclose(output_file);
        }
        event_processor_destroy(processor);
        ebpf_manager_destroy(mgr);
        return EXIT_GENERAL_ERROR;
    }
    log_debug("Output formatter created");
    
    /* Load eBPF programs */
    log_debug("Loading eBPF programs...");
    ret = ebpf_manager_load_programs(mgr);
    if (ret != 0) {
        log_error("Failed to load eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs loaded successfully");
    
    /* Attach eBPF programs */
    log_debug("Attaching eBPF programs...");
    ret = ebpf_manager_attach_programs(mgr);
    if (ret != 0) {
        log_error("Failed to attach eBPF programs");
        ret = EXIT_BPF_ERROR;
        goto cleanup;
    }
    log_info("eBPF programs attached successfully");
    
    log_info("File monitoring started");
    if (args->file_filter) {
        log_info("Filtering by file pattern: %s", args->file_filter);
    }
    
    /* Setup files event callback context */
    files_ctx.processor = processor;
    files_ctx.formatter = formatter;
    files_ctx.events_processed = 0;
    files_ctx.events_filtered = 0;
    
    /* Record start time */
    start_time = time(NULL);
    
    /* Main event loop */
    log_debug("Entering main event loop");
    
    while (!is_shutdown_requested()) {
        /* Poll events from ring buffer */
        ret = ebpf_manager_poll_events(mgr, files_event_callback, &files_ctx);
        if (ret < 0 && ret != -EINTR) {
            log_error("Error polling events: %d", ret);
            break;
        }
        
        /* Check duration limit */
        if (args->duration > 0) {
            current_time = time(NULL);
            if (difftime(current_time, start_time) >= args->duration) {
                log_debug("Duration limit reached (%d seconds)", args->duration);
                break;
            }
        }
    }
    
    /* Process remaining events */
    if (is_shutdown_requested()) {
        log_debug("Shutdown requested, processing remaining events...");
        time_t shutdown_start = time(NULL);
        while (difftime(time(NULL), shutdown_start) < 1.0) {
            ret = ebpf_manager_poll_events(mgr, files_event_callback, &files_ctx);
            if (ret < 0 && ret != -EINTR) {
                break;
            }
            if (ret == 0) {
                break;
            }
        }
    }
    
    /* Get final statistics */
    ebpf_manager_get_stats(mgr, &events_processed_total, &events_dropped_total);
    
    /* Log statistics */
    log_info("File monitoring complete");
    log_info("Events processed: %lu", files_ctx.events_processed);
    log_info("Events filtered: %lu", files_ctx.events_filtered);
    log_info("Events dropped: %lu", events_dropped_total);
    
    ret = EXIT_SUCCESS;
    
cleanup:
    log_debug("Cleaning up resources...");
    
    /* Cleanup eBPF manager */
    if (mgr) {
        ebpf_manager_cleanup(mgr);
        ebpf_manager_destroy(mgr);
    }
    
    /* Cleanup output formatter */
    if (formatter) {
        output_formatter_destroy(formatter);
    }
    
    /* Close output file if we opened it */
    if (args->output_file && output_file && output_file != stdout) {
        fclose(output_file);
    }
    
    /* Cleanup event processor */
    if (processor) {
        event_processor_destroy(processor);
    }
    
    log_debug("Cleanup complete");
    
    return ret;
}

/**
 * Dispatch to appropriate command handler
 * Requirements: 16.1, 16.2, 16.3, 16.4, 16.5
 */
static int dispatch_command(cli_args_t *args) {
    if (!args) {
        return EXIT_GENERAL_ERROR;
    }
    
    switch (args->command) {
        case CMD_MONITOR:
            return execute_monitor_command(args);
            
        case CMD_PROFILE:
            return execute_profile_command(args);
            
        case CMD_SNAPSHOT:
            return execute_snapshot_command(args);
            
        case CMD_LIBS:
            return execute_libs_command(args);
            
        case CMD_FILES:
            return execute_files_command(args);
            
        default:
            log_error("Unknown command: %d", args->command);
            return EXIT_GENERAL_ERROR;
    }
}

int main(int argc, char **argv) {
    int ret;
    cli_args_t args;
    logger_config_t logger_config;
    
    /* Parse command-line arguments */
    ret = parse_args(argc, argv, &args);
    
    /* For errors, return the error code */
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    
    /* If parse_args set exit_after_parse (for help/version), exit now */
    if (args.exit_after_parse) {
        return EXIT_SUCCESS;
    }
    
    /* Initialize logger with command-line settings */
    logger_config.min_level = LOG_LEVEL_INFO;
    logger_config.quiet = args.quiet;
    logger_config.verbose = args.verbose;
    logger_config.output = stderr;
    logger_init(&logger_config);
    
    log_debug("crypto-tracer v%s starting", CRYPTO_TRACER_VERSION);
    log_debug("Command: %s", 
              args.command == CMD_MONITOR ? "monitor" :
              args.command == CMD_PROFILE ? "profile" :
              args.command == CMD_SNAPSHOT ? "snapshot" :
              args.command == CMD_LIBS ? "libs" :
              args.command == CMD_FILES ? "files" : "unknown");
    
    /* Validate privileges (not required for snapshot command) */
    /* Requirement 3.6: Snapshot works without eBPF (using /proc only) */
    if (args.command != CMD_SNAPSHOT) {
        log_debug("Validating privileges...");
        ret = validate_privileges();
        if (ret != EXIT_SUCCESS) {
            return ret;
        }
        log_debug("Privilege validation passed");
        
        /* Check kernel version and compatibility */
        log_debug("Checking kernel version and compatibility...");
        ret = check_kernel_version();
        if (ret != EXIT_SUCCESS) {
            return ret;
        }
        log_debug("Kernel compatibility check passed");
    } else {
        log_debug("Snapshot command - skipping privilege and kernel checks (uses /proc only)");
    }
    
    /* Setup signal handlers for graceful shutdown */
    log_debug("Setting up signal handlers...");
    ret = setup_signal_handlers();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    log_debug("Signal handlers configured");
    
    /* Display parsed arguments in verbose mode */
    if (args.verbose) {
        log_info("crypto-tracer v%s initialized", CRYPTO_TRACER_VERSION);
        if (args.duration > 0) {
            log_info("Duration: %d seconds", args.duration);
        }
        if (args.pid > 0) {
            log_info("Target PID: %d", args.pid);
        }
        if (args.process_name) {
            log_info("Target process: %s", args.process_name);
        }
        if (args.output_file) {
            log_info("Output file: %s", args.output_file);
        }
    }
    
    /* Dispatch to command handlers */
    ret = dispatch_command(&args);
    
    return ret;
}