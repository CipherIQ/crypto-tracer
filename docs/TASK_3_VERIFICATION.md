# Task 3 Verification: Command-Line Argument Parser

## Implementation Summary

Successfully implemented a comprehensive command-line argument parser for crypto-tracer with support for all commands and options specified in the requirements.

## Features Implemented

### 1. Command Support
- ✅ `monitor` - Monitor crypto operations in real-time
- ✅ `profile` - Generate detailed profile of a process
- ✅ `snapshot` - Take quick snapshot of all crypto usage
- ✅ `libs` - List loaded cryptographic libraries
- ✅ `files` - Track access to cryptographic files
- ✅ `help [command]` - Show help for specific commands
- ✅ `version` - Show version information

### 2. Global Options
- ✅ `-h, --help` - Show help message
- ✅ `-v, --verbose` - Enable verbose output
- ✅ `-q, --quiet` - Quiet mode (minimal output)
- ✅ `-o, --output FILE` - Write output to file
- ✅ `-f, --format FORMAT` - Output format selection
- ✅ `--no-redact` - Disable privacy path redaction

### 3. Command-Specific Options
- ✅ `-d, --duration SECONDS` - Duration for monitoring
- ✅ `-p, --pid PID` - Target process ID
- ✅ `-n, --name NAME` - Target process name
- ✅ `-l, --library LIB` - Filter by library name
- ✅ `-F, --file PATTERN` - Filter by file path
- ✅ `--follow-children` - Follow child processes (profile only)

### 4. Output Formats
- ✅ `json-stream` - One JSON object per line (default)
- ✅ `json-array` - JSON array of events
- ✅ `json-pretty` - Pretty-printed JSON
- ✅ `summary` - Human-readable summary

### 5. Validation Features
- ✅ Command validation with helpful error messages
- ✅ Option validation (PID, duration, format)
- ✅ Argument combination validation
- ✅ Mutually exclusive option detection (verbose/quiet)
- ✅ Command-specific requirement validation (profile needs --pid or --name)
- ✅ Warning messages for ignored options

### 6. Help System
- ✅ General usage information (Requirement 11.2)
- ✅ Command-specific help (Requirement 11.3)
- ✅ Practical examples (Requirement 11.4)
- ✅ Helpful error messages with suggestions (Requirement 11.5)

### 7. Version Information
- ✅ Version number display (Requirement 11.1)
- ✅ Build date
- ✅ Kernel support information
- ✅ License information

## Test Results

### Basic Command Tests
```bash
# Help display
$ ./build/crypto-tracer --help
✅ Shows general usage information

$ ./build/crypto-tracer help monitor
✅ Shows monitor-specific help

# Version display
$ ./build/crypto-tracer --version
✅ Shows version 1.0.0 with build date and license

$ ./build/crypto-tracer version
✅ Alternative version command works
```

### Command Execution Tests
```bash
# Monitor command
$ sudo ./build/crypto-tracer monitor --duration 5 --verbose
✅ Parses duration correctly
✅ Shows verbose output

# Profile command
$ sudo ./build/crypto-tracer profile --pid 1234 --verbose
✅ Parses PID correctly
✅ Sets default duration to 30 seconds

# Snapshot command
$ sudo ./build/crypto-tracer snapshot --format summary --verbose
✅ Parses format correctly
✅ Executes without requiring duration/pid

# Libs command
$ sudo ./build/crypto-tracer libs --library libssl --duration 10
✅ Parses library filter
✅ Parses duration

# Files command
$ sudo ./build/crypto-tracer files --file '/etc/ssl/*.pem'
✅ Parses file filter with glob pattern
```

### Complex Option Tests
```bash
# Multiple options
$ sudo ./build/crypto-tracer monitor --pid 1234 --name nginx \
  --library libssl --file '/etc/*.pem' --output test.json \
  --format json-array --no-redact --verbose
✅ All options parsed correctly

# Profile with follow-children
$ sudo ./build/crypto-tracer profile --name nginx \
  --follow-children --duration 60 --output profile.json
✅ follow-children flag parsed
✅ Custom duration overrides default
```

### Error Handling Tests
```bash
# No command
$ ./build/crypto-tracer
✅ Error: No command specified (exit code 2)

# Invalid command
$ ./build/crypto-tracer invalid-command
✅ Error: Unknown command (exit code 2)

# Missing required option
$ ./build/crypto-tracer profile
✅ Error: profile requires --pid or --name (exit code 2)

# Invalid duration
$ ./build/crypto-tracer monitor --duration abc
✅ Error: Invalid duration (exit code 2)

# Invalid PID
$ ./build/crypto-tracer monitor --pid abc
✅ Error: Invalid PID (exit code 2)

# Invalid format
$ ./build/crypto-tracer monitor --format invalid
✅ Error: Invalid format with valid options listed (exit code 2)

# Mutually exclusive options
$ ./build/crypto-tracer monitor --verbose --quiet
✅ Error: Cannot use together (exit code 2)

# Negative values
$ ./build/crypto-tracer monitor --duration -5
✅ Error: Invalid duration (exit code 2)

$ ./build/crypto-tracer monitor --pid -1
✅ Error: Invalid PID (exit code 2)

# Extra arguments
$ ./build/crypto-tracer monitor extra-arg
✅ Error: Unexpected argument (exit code 2)

# Unknown option
$ ./build/crypto-tracer monitor --unknown-option
✅ Error: Unrecognized option with help suggestion (exit code 2)
```

### Validation Tests
```bash
# Snapshot with ignored options
$ sudo ./build/crypto-tracer snapshot --duration 10
✅ Warning: --duration is ignored for snapshot

$ sudo ./build/crypto-tracer snapshot --pid 1234
✅ Warning: --pid and --name are ignored

$ sudo ./build/crypto-tracer snapshot --library libssl
✅ Warning: filters are ignored

# follow-children on non-profile command
$ sudo ./build/crypto-tracer monitor --follow-children
✅ Warning: --follow-children only supported for profile
```

### Quiet Mode Test
```bash
$ sudo ./build/crypto-tracer monitor --quiet
✅ No output (suppressed successfully)
```

## Requirements Coverage

### Requirement 1.1-1.6 (Monitor Command)
✅ All monitor command options implemented and validated

### Requirement 11.1 (Version Information)
✅ Version display with build date, kernel support, and license

### Requirement 11.2 (General Help)
✅ Usage information with all commands and global options

### Requirement 11.3 (Command-Specific Help)
✅ Detailed help for each command with options and examples

### Requirement 11.4 (Practical Examples)
✅ Examples included in both general and command-specific help

### Requirement 11.5 (Error Messages)
✅ Helpful error messages with suggestions for --help

## Exit Codes

- ✅ `0` (EXIT_SUCCESS) - Successful execution or help/version display
- ✅ `2` (EXIT_ARGUMENT_ERROR) - Invalid arguments or options
- ✅ `3` (EXIT_PRIVILEGE_ERROR) - Insufficient privileges (from task 2)
- ✅ `4` (EXIT_KERNEL_ERROR) - Kernel compatibility issues (from task 2)

## Code Quality

- ✅ No compiler warnings with `-Wall -Wextra`
- ✅ C11 standard compliance
- ✅ Proper error handling with descriptive messages
- ✅ Clean separation of concerns (parsing, validation, help display)
- ✅ Consistent coding style with existing codebase
- ✅ Proper license headers (GPL-3.0-or-later)

## Files Modified

1. **src/include/crypto_tracer.h**
   - Added command_type_t enum
   - Added output_format_t enum
   - Added cli_args_t structure
   - Added function prototypes for parsing and help

2. **src/main.c**
   - Implemented print_version()
   - Implemented print_usage()
   - Implemented print_command_help()
   - Implemented init_args()
   - Implemented parse_format()
   - Implemented parse_command()
   - Implemented validate_args()
   - Implemented parse_args()
   - Updated main() to use argument parser

## Integration

The argument parser integrates seamlessly with existing code:
- Uses existing privilege validation (task 2)
- Uses existing kernel version checking (task 2)
- Prepares for future command dispatch implementation
- Maintains consistent error handling and exit codes

## Next Steps

The argument parser is complete and ready for integration with:
- Task 4: Core data structures
- Task 5: eBPF programs
- Task 6: eBPF manager
- Command-specific implementations (tasks 15-18)

All parsed arguments are stored in the cli_args_t structure and ready to be used by subsequent components.
