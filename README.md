# crypto-tracer

A standalone eBPF-based command-line tool for monitoring cryptographic operations on Linux systems.

## Overview

crypto-tracer provides real-time visibility into cryptographic behavior by observing file access, library loading, and API calls related to cryptographic operations. It uses kernel-level instrumentation (eBPF) to monitor crypto activity with minimal performance impact (<0.5% CPU overhead).

**Key Features:**
- 🔍 **Real-time monitoring** of crypto file access and library loading
- 📊 **Process profiling** with detailed crypto usage statistics
- 📸 **System snapshots** for crypto inventory and compliance
- 🔒 **Privacy-first** with automatic path redaction
- ⚡ **Lightweight** with <50MB memory footprint
- 🛡️ **Safe** read-only operation, no system modifications
- 🌐 **Cross-kernel** compatible (Linux 4.15+)

**Use Cases:**
- Security auditing and threat detection
- Troubleshooting certificate and key loading issues
- Compliance reporting and crypto inventory
- Development verification and testing
- Research into cryptographic behavior patterns

## Build Requirements

### Essential Dependencies
- **gcc** - C compiler for user-space code
- **clang** - LLVM compiler for eBPF programs
- **libbpf-dev** - eBPF library and headers
- **libelf-dev** - ELF library for BPF loading
- **zlib1g-dev** - Compression library

### Optional Dependencies
- **bpftool** - For skeleton generation (recommended)
- **llvm-strip** - For eBPF program optimization

### Installation on Ubuntu/Debian
```bash
sudo apt update
sudo apt install gcc clang libbpf-dev libelf-dev zlib1g-dev
sudo apt install linux-tools-common linux-tools-generic  # for bpftool
```

### Installation on RHEL/Fedora
```bash
sudo dnf install gcc clang libbpf-devel elfutils-libelf-devel zlib-devel
sudo dnf install bpftool
```

## Building

### Quick Start
```bash
# Check dependencies
make check-deps

# Build the project
make

# Build with static linking (for distribution)
make static

# Build with debug symbols
make debug
```

### Build System Features

#### CO-RE (Compile Once, Run Everywhere) Strategy
The build system implements BPF CO-RE for maximum compatibility:

1. **Auto-generate vmlinux.h**: Extracts kernel structures from running kernel's BTF
2. **Fallback support**: Uses pre-built vmlinux.h for non-BTF kernels
3. **BPF_CORE_READ()**: Configured for portable field access

#### Skeleton Generation
- Uses `bpftool gen skeleton` to embed eBPF programs in binary
- Enables single-binary distribution
- Automatic dependency tracking

#### Static Linking Option
```bash
make static
```
Produces a fully static binary with no external dependencies (except glibc/musl).

### Build Targets

| Target | Description |
|--------|-------------|
| `all` | Build main program (default) |
| `test` | Build and run all tests |
| `clean` | Remove build artifacts |
| `install` | Install to system |
| `check-deps` | Verify build dependencies |
| `config` | Show build configuration |
| `debug` | Build with debug symbols |
| `static` | Build with static linking |

## Project Structure

```
crypto-tracer/
├── src/
│   ├── main.c                    # Main entry point
│   ├── include/                  # User-space headers
│   │   ├── crypto_tracer.h
│   │   └── ebpf_manager.h
│   └── ebpf/                     # eBPF programs
│       ├── common.h              # Shared definitions
│       ├── vmlinux_fallback.h    # Fallback kernel headers
│       ├── file_open_trace.bpf.c
│       ├── lib_load_trace.bpf.c
│       ├── process_exec_trace.bpf.c
│       ├── process_exit_trace.bpf.c
│       └── openssl_api_trace.bpf.c
├── tests/
│   ├── unit/                     # Unit tests
│   └── integration/              # Integration tests
├── build/                        # Build artifacts
│   ├── vmlinux.h                 # Generated kernel headers
│   ├── *.bpf.o                   # Compiled eBPF programs
│   ├── *.skel.h                  # Generated skeletons
│   └── crypto-tracer             # Final binary
├── .kiro/                        # Kiro IDE configuration
│   ├── docs/                     # Task verification documents
│   ├── specs/                    # Project specifications
│   └── steering/                 # AI assistant guidance
└── Makefile                      # Build system
```

## Development

### Adding New eBPF Programs
1. Create `src/ebpf/new_program.bpf.c`
2. Include common headers and define SEC() functions
3. The build system will automatically:
   - Compile to `build/new_program.bpf.o`
   - Generate `build/new_program.skel.h`
   - Include in final binary

### Build System Internals
- **vmlinux.h generation**: `bpftool btf dump file /sys/kernel/btf/vmlinux`
- **eBPF compilation**: `clang -target bpf -O2`
- **Skeleton generation**: `bpftool gen skeleton`
- **Static linking**: Links libbpf, libelf, and zlib statically

## Troubleshooting

### Common Build Issues

**"bpftool not found"**
```bash
# Ubuntu/Debian
sudo apt install linux-tools-common linux-tools-generic

# RHEL/Fedora  
sudo dnf install bpftool
```

**"vmlinux.h generation failed"**
- System may not have BTF support
- Build system automatically falls back to `vmlinux_fallback.h`
- This is normal on older kernels (<5.4)

**"clang not found"**
```bash
sudo apt install clang  # Ubuntu/Debian
sudo dnf install clang  # RHEL/Fedora
```

**Static linking fails**
- Ensure static versions of libraries are installed
- On Ubuntu: `sudo apt install libbpf-dev:amd64 libelf-dev:amd64`

### Kernel Compatibility
- **Minimum**: Linux 4.15+ (basic eBPF support)
- **Recommended**: Linux 5.8+ (CAP_BPF, BTF support)
- **CO-RE**: Automatic adaptation to kernel versions

## Usage

### Quick Start

```bash
# Monitor all crypto activity (requires sudo)
sudo ./build/crypto-tracer monitor --duration 60

# Profile a specific process
sudo ./build/crypto-tracer profile --pid 1234 --duration 30

# Take a system snapshot (no sudo needed!)
./build/crypto-tracer snapshot

# Monitor specific files
sudo ./build/crypto-tracer files --file "*.pem" --duration 30

# Track library loading
sudo ./build/crypto-tracer libs --duration 30
```

### Commands

#### monitor - Real-time Crypto Monitoring
Monitor all cryptographic activity system-wide:

```bash
# Basic monitoring
sudo ./build/crypto-tracer monitor

# Monitor for specific duration
sudo ./build/crypto-tracer monitor --duration 60

# Filter by process
sudo ./build/crypto-tracer monitor --pid 1234
sudo ./build/crypto-tracer monitor --name nginx

# Filter by file or library
sudo ./build/crypto-tracer monitor --file "*.pem"
sudo ./build/crypto-tracer monitor --library libssl

# Output to file
sudo ./build/crypto-tracer monitor --output events.json

# Different output formats
sudo ./build/crypto-tracer monitor --format json-stream   # One JSON per line (default)
sudo ./build/crypto-tracer monitor --format json-array    # JSON array
sudo ./build/crypto-tracer monitor --format json-pretty   # Pretty-printed
```

#### profile - Process Profiling
Generate detailed crypto usage profile for a specific process:

```bash
# Profile by PID
sudo ./build/crypto-tracer profile --pid 1234 --duration 30

# Profile by name
sudo ./build/crypto-tracer profile --name nginx --duration 30

# Save profile to file
sudo ./build/crypto-tracer profile --pid 1234 --output profile.json
```

**Output includes:**
- Process metadata (PID, name, command line, user)
- All loaded crypto libraries
- All accessed crypto files with access counts
- API call statistics (if available)
- Aggregated statistics

#### snapshot - System Inventory
Take instant snapshot of all processes using cryptography:

```bash
# Basic snapshot (no sudo required!)
./build/crypto-tracer snapshot

# Save to file
./build/crypto-tracer snapshot --output inventory.json

# Pretty format
./build/crypto-tracer snapshot --format json-pretty
```

**Output includes:**
- All processes with crypto libraries loaded
- Open crypto files per process
- System summary statistics

#### files - File Access Tracking
Monitor access to cryptographic files:

```bash
# Monitor all crypto files
sudo ./build/crypto-tracer files --duration 30

# Filter by pattern
sudo ./build/crypto-tracer files --file "*.pem"
sudo ./build/crypto-tracer files --file "/etc/ssl/*"

# Filter by process
sudo ./build/crypto-tracer files --pid 1234
```

#### libs - Library Loading Tracking
Monitor cryptographic library loading:

```bash
# Monitor all crypto libraries
sudo ./build/crypto-tracer libs --duration 30

# Filter by library name
sudo ./build/crypto-tracer libs --library libssl

# Filter by process
sudo ./build/crypto-tracer libs --name nginx
```

### Common Options

| Option | Description |
|--------|-------------|
| `--duration N` | Monitor for N seconds (default: unlimited) |
| `--output FILE` | Write output to file instead of stdout |
| `--format FORMAT` | Output format: json-stream, json-array, json-pretty |
| `--pid PID` | Filter by process ID |
| `--name NAME` | Filter by process name |
| `--library LIB` | Filter by library name |
| `--file PATTERN` | Filter by file path pattern |
| `--no-redact` | Disable privacy filtering |
| `--verbose` | Enable verbose logging |
| `--quiet` | Suppress non-essential output |
| `--help` | Show help message |
| `--version` | Show version information |

### Examples

**Example 1: Monitor web server crypto activity**
```bash
# Monitor nginx for 60 seconds
sudo ./build/crypto-tracer monitor --name nginx --duration 60 --output nginx-crypto.json
```

**Example 2: Profile application startup**
```bash
# Start your app in one terminal
./my-app &
APP_PID=$!

# Profile it in another terminal
sudo ./build/crypto-tracer profile --pid $APP_PID --duration 30 | python3 -m json.tool
```

**Example 3: Audit certificate access**
```bash
# Monitor certificate file access
sudo ./build/crypto-tracer files --file "*.crt" --duration 300 > cert-access.json

# Analyze with jq
cat cert-access.json | jq -r '.file' | sort | uniq -c
```

**Example 4: Generate compliance report**
```bash
# Take snapshot
./build/crypto-tracer snapshot --output crypto-inventory-$(date +%Y%m%d).json

# Extract summary
cat crypto-inventory-*.json | jq '.summary'
```

**Example 5: Debug SSL/TLS issues**
```bash
# Monitor in one terminal
sudo ./build/crypto-tracer monitor --name myapp --verbose

# Run your app in another terminal
./myapp

# Watch for certificate loading errors
```

See [DEMO.md](DEMO.md) for more detailed usage scenarios and examples.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/crypto-tracer.git
cd crypto-tracer

# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install gcc clang libbpf-dev libelf-dev zlib1g-dev linux-tools-common linux-tools-generic

# Build
make

# Optional: Install system-wide
sudo make install

# Optional: Grant capabilities (run without sudo)
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer
```

### System Requirements

**Kernel Requirements:**
- Linux kernel 4.15 or later
- eBPF support enabled (CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y)
- BTF support recommended (CONFIG_DEBUG_INFO_BTF=y)

**Privileges Required:**

crypto-tracer needs special privileges to load eBPF programs. You have three options:

**Option 1: Run with sudo (Simplest)**
```bash
sudo ./build/crypto-tracer monitor
```
This works on all systems but requires entering your password each time.

**Option 2: Grant CAP_BPF capability (Recommended for kernel 5.8+)**
```bash
# Grant capabilities to the binary (one-time setup)
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer

# Now you can run without sudo
./build/crypto-tracer monitor
```
This is the most secure option on modern kernels. The capabilities are:
- `cap_bpf` - Allows loading eBPF programs
- `cap_perfmon` - Allows reading performance events

**Option 3: Grant CAP_SYS_ADMIN capability (For older kernels < 5.8)**
```bash
# For kernels that don't support CAP_BPF
sudo setcap cap_sys_admin+ep ./build/crypto-tracer

# Now you can run without sudo
./build/crypto-tracer monitor
```

**Important Notes:**
- Capabilities are tied to the binary file. If you rebuild, you must re-grant them.
- The `snapshot` command doesn't need any special privileges (it only reads /proc).
- To check current capabilities: `getcap ./build/crypto-tracer`
- To remove capabilities: `sudo setcap -r ./build/crypto-tracer`

**For detailed explanation and troubleshooting, see [PRIVILEGES.md](PRIVILEGES.md)**

**Supported Distributions:**
- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- RHEL 8, 9
- Fedora 36+
- Amazon Linux 2023
- Alpine Linux 3.17+

### Verifying Installation

```bash
# Check version
./build/crypto-tracer --version

# Test with snapshot (no sudo needed)
./build/crypto-tracer snapshot

# Test monitoring (requires sudo)
sudo ./build/crypto-tracer monitor --duration 5
```

## Output Format

crypto-tracer outputs structured JSON for easy parsing and integration.

### Event Types

**file_open** - Crypto file access
```json
{
  "event_type": "file_open",
  "timestamp": "2024-11-18T12:34:56.789012Z",
  "pid": 1234,
  "uid": 1000,
  "process": "nginx",
  "file": "/etc/ssl/certs/server.crt",
  "file_type": "certificate",
  "flags": "O_RDONLY"
}
```

**lib_load** - Crypto library loading
```json
{
  "event_type": "lib_load",
  "timestamp": "2024-11-18T12:34:56.789012Z",
  "pid": 1234,
  "process": "nginx",
  "library": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
  "library_name": "libssl"
}
```

See [.kiro/docs/JSON_OUTPUT_EXAMPLES.md](.kiro/docs/JSON_OUTPUT_EXAMPLES.md) for complete format documentation.

## Privacy and Security

### Privacy Features

**Automatic Path Redaction:**
- `/home/alice/key.pem` → `/home/USER/key.pem`
- `/root/cert.pem` → `/home/ROOT/cert.pem`
- System paths preserved: `/etc/ssl/`, `/usr/lib/`

**Disable with:** `--no-redact`

**Data Protection:**
- Never logs private key content
- Never logs passwords or plaintext data
- Only captures metadata (filenames, timestamps, PIDs)

### Security Considerations

**Read-Only Operation:**
- No system modifications
- No file creation (except specified output file)
- eBPF programs verified by kernel for safety

**Safe to Use:**
- Won't crash monitored applications
- Won't affect system stability
- Graceful cleanup on exit

## Performance

**Typical Overhead:**
- CPU: <0.5% average, <2% peak per core
- Memory: <50MB RSS
- Event processing: Up to 5,000 events/second
- Startup time: <2 seconds

**Tested Scenarios:**
- High-traffic web servers (nginx, apache)
- Database servers (PostgreSQL, MySQL)
- Long-running monitoring (24+ hours)
- High event volumes (1M+ events)

## Troubleshooting

### Permission Denied

```bash
# Error: Permission denied
# Solution: Run with sudo or grant capabilities
sudo ./build/crypto-tracer monitor

# Or grant capabilities (one-time)
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer
./build/crypto-tracer monitor  # Now works without sudo
```

### No Events Captured

**Check if target process is actually using crypto:**
```bash
# Check loaded libraries
lsof -p <PID> | grep -E "libssl|libcrypto"

# Check open files
lsof -p <PID> | grep -E "\.pem|\.crt|\.key"
```

**Verify eBPF programs loaded:**
```bash
sudo ./build/crypto-tracer monitor --verbose
```

### Child Process Events Missing

When profiling by PID, child processes have different PIDs. Use `--name` to match by process name instead:

```bash
# Instead of:
sudo ./build/crypto-tracer profile --pid 1234

# Use:
sudo ./build/crypto-tracer profile --name myapp
```

### Kernel Too Old

```bash
# Check kernel version
uname -r

# Minimum required: 4.15
# Recommended: 5.8+
```

If kernel is too old, consider upgrading or using a newer distribution.

### Build Issues

See the "Troubleshooting" section under "Building" above for common build issues.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Development Setup:**
```bash
# Build with debug symbols
make debug

# Run tests
make test

# Run specific test suite
make test-unit
make test-integration

# Check for memory leaks
make memcheck
```

## License

GPL-3.0-or-later

Copyright (c) 2025 Graziano Labs Corp.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [libbpf](https://github.com/libbpf/libbpf)
- Uses BPF CO-RE (Compile Once - Run Everywhere) technology
- Inspired by the eBPF community and tools like bpftrace
