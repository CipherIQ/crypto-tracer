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
#include "include/crypto_tracer.h"

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
    fprintf(stderr, "Error: Insufficient privileges to run crypto-tracer\n\n");
    fprintf(stderr, "crypto-tracer requires one of the following:\n");
    fprintf(stderr, "  1. Run as root: sudo crypto-tracer [options]\n");
    
    if (major > CAP_BPF_KERNEL_MAJOR || 
        (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
        fprintf(stderr, "  2. Grant CAP_BPF capability: sudo setcap cap_bpf+ep /path/to/crypto-tracer\n");
        fprintf(stderr, "  3. Grant CAP_SYS_ADMIN capability: sudo setcap cap_sys_admin+ep /path/to/crypto-tracer\n");
    } else {
        fprintf(stderr, "  2. Grant CAP_SYS_ADMIN capability: sudo setcap cap_sys_admin+ep /path/to/crypto-tracer\n");
        fprintf(stderr, "     (CAP_BPF is not available on kernel %d.%d, requires 5.8+)\n", major, minor);
    }
    
    fprintf(stderr, "\nNote: CAP_BPF is the preferred capability on kernel 5.8+\n");
    
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
        fprintf(stderr, "Error: Failed to get kernel version: %s\n", strerror(errno));
        return EXIT_KERNEL_ERROR;
    }
    
    /* Parse kernel version */
    if (parse_kernel_version(uts.release, &major, &minor, &patch) != 0) {
        fprintf(stderr, "Error: Failed to parse kernel version: %s\n", uts.release);
        return EXIT_KERNEL_ERROR;
    }
    
    /* Requirement 9.1: Check for minimum kernel version 4.15+ */
    if (major < MIN_KERNEL_MAJOR || 
        (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR)) {
        fprintf(stderr, "Error: Kernel version %d.%d.%d is not supported\n", 
                major, minor, patch);
        fprintf(stderr, "\ncrypto-tracer requires Linux kernel 4.15 or later\n");
        fprintf(stderr, "Your kernel: %s (version %d.%d.%d)\n", 
                uts.release, major, minor, patch);
        fprintf(stderr, "\nPlease upgrade your kernel to use crypto-tracer\n");
        return EXIT_KERNEL_ERROR;
    }
    
    /* Requirement 9.2: Detect CAP_BPF support on kernel 5.8+ */
    if (major > CAP_BPF_KERNEL_MAJOR || 
        (major == CAP_BPF_KERNEL_MAJOR && minor >= CAP_BPF_KERNEL_MINOR)) {
        /* CAP_BPF is available - enhanced security mode */
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: Kernel %d.%d.%d supports CAP_BPF (enhanced security)\n",
                    major, minor, patch);
        }
    } else {
        /* Older kernel - will use CAP_SYS_ADMIN */
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: Kernel %d.%d.%d requires CAP_SYS_ADMIN (CAP_BPF not available)\n",
                    major, minor, patch);
        }
    }
    
    /* Check for eBPF support by looking for /sys/kernel/btf/vmlinux or /proc/config.gz */
    if (access("/sys/kernel/btf/vmlinux", F_OK) == 0) {
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: BTF support detected (CO-RE enabled)\n");
        }
    } else {
        if (getenv("CRYPTO_TRACER_VERBOSE")) {
            fprintf(stderr, "Info: BTF not available, using fallback headers\n");
        }
    }
    
    /* Requirement 9.4: Graceful feature detection - always succeed if kernel >= 4.15 */
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    int ret;
    cli_args_t args;
    
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
    
    /* Validate privileges */
    ret = validate_privileges();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    
    /* Check kernel version and compatibility */
    ret = check_kernel_version();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    
    /* Setup signal handlers for graceful shutdown */
    ret = setup_signal_handlers();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    
    /* Display parsed arguments in verbose mode */
    if (args.verbose) {
        printf("crypto-tracer v%s\n", CRYPTO_TRACER_VERSION);
        printf("Command: %s\n", 
               args.command == CMD_MONITOR ? "monitor" :
               args.command == CMD_PROFILE ? "profile" :
               args.command == CMD_SNAPSHOT ? "snapshot" :
               args.command == CMD_LIBS ? "libs" :
               args.command == CMD_FILES ? "files" : "unknown");
        if (args.duration > 0) {
            printf("Duration: %d seconds\n", args.duration);
        }
        if (args.pid > 0) {
            printf("Target PID: %d\n", args.pid);
        }
        if (args.process_name) {
            printf("Target process: %s\n", args.process_name);
        }
        if (args.output_file) {
            printf("Output file: %s\n", args.output_file);
        }
        printf("Privilege and kernel checks passed\n");
    }
    
    /* TODO: Dispatch to command handlers (will be implemented in later tasks) */
    if (!args.quiet) {
        printf("Command parsing successful. Command execution not yet implemented.\n");
    }
    
    return EXIT_SUCCESS;
}