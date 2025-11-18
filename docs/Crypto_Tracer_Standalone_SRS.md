# Software Requirements Specification (SRS)
# Crypto-Tracer: Standalone Runtime Cryptographic Behavior Analysis Tool

**Document Version:** 1.0  
**Date:** November 17, 2025  
**Project:** crypto-tracer - Standalone eBPF-based Crypto Monitoring CLI  
**Status:** Draft for Review  
**Classification:** Open Source Project Specification

**Document Control:**
- **Author:** Requirements Engineering Team
- **Reviewers:** Architecture Team, Security Team
- **Approvers:** Project Lead, Technical Architect
- **Change History:**

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0 | 2025-11-17 | Requirements Team | Initial draft for standalone tool |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Overall Description](#2-overall-description)
3. [Specific Requirements](#3-specific-requirements)
4. [System Features](#4-system-features)
5. [External Interface Requirements](#5-external-interface-requirements)
6. [Non-Functional Requirements](#6-non-functional-requirements)
7. [Appendices](#7-appendices)

---

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification (SRS) describes the functional and non-functional requirements for **crypto-tracer**, a standalone command-line tool for monitoring and analyzing cryptographic operations on Linux systems using eBPF (Extended Berkeley Packet Filter) technology.

**Intended Audience:**
- Open source developers implementing the tool
- Security researchers evaluating cryptographic usage
- System administrators troubleshooting crypto issues
- DevOps engineers auditing production systems
- Compliance officers documenting crypto inventory

**Document Purpose:**
This document serves as the complete specification for building crypto-tracer as an independent, standalone utility with no dependencies on external platforms or frameworks. It can be used as-is or as a foundation for integration into larger systems.

### 1.2 Scope

**Product Name:** crypto-tracer

**Product Overview:**
crypto-tracer is a lightweight, standalone command-line utility that uses Linux eBPF technology to observe and record cryptographic operations in real-time. The tool is designed to answer questions like:

- "What processes are using cryptography on this system?"
- "Which certificates and keys are being accessed right now?"
- "What cryptographic libraries are loaded by my application?"
- "Is my application really using TLS 1.3, or falling back to TLS 1.2?"

**Key Capabilities:**
1. **Process Discovery:** Automatically detect processes using cryptography
2. **Library Tracking:** Monitor loading of OpenSSL, GnuTLS, libsodium, etc.
3. **File Access Monitoring:** Track access to certificates, private keys, and keystores
4. **API Call Tracing:** Observe cryptographic API invocations (OpenSSL, GnuTLS)
5. **Real-Time Streaming:** Live output of crypto events as they happen
6. **JSON Output:** Machine-readable output for integration with other tools
7. **Privacy-Preserving:** Redact sensitive paths and data by default

**Primary Use Cases:**
1. **Security Auditing:** Identify all crypto usage during an audit period
2. **Troubleshooting:** Debug why an application can't find its certificate
3. **Compliance:** Document which crypto libraries are in use
4. **Development:** Verify that your application loads crypto correctly
5. **Research:** Study cryptographic behavior of applications

**Goals:**
- Single-binary distribution (no complex dependencies)
- Minimal performance overhead (<1% CPU)
- Easy to use (simple command-line interface)
- Safe operation (read-only, no system modifications)
- Privacy-aware (no sensitive data in output)

**Out of Scope (For v1.0):**
- Integration with external platforms or dashboards
- Long-term data storage or databases
- Network traffic decryption or MITM
- Active probing or modification of system behavior
- Windows or macOS support (Linux-only)
- Configuration management systems integration
- Correlation with static configuration files
- CBOM or SBOM generation (output is generic JSON)

### 1.3 Definitions, Acronyms, and Abbreviations

| Term | Definition |
|------|------------|
| **eBPF** | Extended Berkeley Packet Filter - Linux kernel technology for safe, sandboxed programs |
| **BPF** | Berkeley Packet Filter - predecessor to eBPF |
| **Syscall** | System call - interface between user-space applications and the kernel |
| **Uprobe** | User-space probe - dynamic tracing of user-space functions |
| **Kprobe** | Kernel probe - dynamic tracing of kernel functions |
| **Tracepoint** | Static instrumentation points in the kernel |
| **Ring Buffer** | Lock-free data structure for passing events from kernel to user-space |
| **BTF** | BPF Type Format - metadata describing BPF program types |
| **CO-RE** | Compile Once, Run Everywhere - eBPF portability framework |
| **libbpf** | User-space library for loading and interacting with eBPF programs |
| **PID** | Process ID - unique identifier for a running process |
| **PPID** | Parent Process ID - PID of the parent process |
| **UID** | User ID - numeric identifier for a user account |
| **GID** | Group ID - numeric identifier for a group |
| **TLS** | Transport Layer Security - cryptographic protocol for secure communication |
| **SSL** | Secure Sockets Layer - predecessor to TLS |
| **X.509** | Standard format for public key certificates |
| **PEM** | Privacy-Enhanced Mail - text encoding format for certificates and keys |
| **DER** | Distinguished Encoding Rules - binary encoding for certificates |
| **PKCS** | Public-Key Cryptography Standards - various cryptographic standards |
| **JSON** | JavaScript Object Notation - text-based data format |
| **CLI** | Command-Line Interface - text-based user interface |

### 1.4 References

**Standards and Specifications:**
1. eBPF Documentation - https://ebpf.io/
2. Linux Kernel eBPF Documentation - https://www.kernel.org/doc/html/latest/bpf/
3. BPF CO-RE (Compile Once - Run Everywhere) - https://nakryiko.com/posts/bpf-portability-and-co-re/
4. libbpf API Documentation - https://libbpf.readthedocs.io/
5. JSON Specification (RFC 8259) - https://datatracker.ietf.org/doc/html/rfc8259

**Technical Documentation:**
1. OpenSSL API Reference - https://www.openssl.org/docs/
2. GnuTLS API Documentation - https://www.gnutls.org/manual/
3. Linux System Call Manual - https://man7.org/linux/man-pages/man2/syscalls.2.html
4. proc(5) Manual Page - /proc filesystem documentation

**Related Tools:**
1. bpftool - BPF program inspection utility
2. bpftrace - High-level tracing language for eBPF
3. strace - System call tracer

### 1.5 Overview

This SRS is organized according to IEEE Std 830-1998 recommendations:

**Section 2 (Overall Description):** Provides context for crypto-tracer, including product perspective as a standalone tool, user characteristics, constraints, and dependencies.

**Section 3 (Specific Requirements):** Details functional requirements organized by feature area, covering eBPF monitoring, event processing, and output generation.

**Section 4 (System Features):** Describes major features using practical use case scenarios that demonstrate real-world applications.

**Section 5 (External Interface Requirements):** Specifies the command-line interface and output formats.

**Section 6 (Non-Functional Requirements):** Covers performance, security, reliability, portability, and other quality attributes.

**Section 7 (Appendices):** Contains supporting information including data dictionary, JSON schema, and usage examples.

---

## 2. Overall Description

### 2.1 Product Perspective

crypto-tracer is a **completely standalone tool** with no dependencies on external platforms, services, or frameworks. It is designed as a single-purpose utility that can be:

- Downloaded and run immediately (single binary)
- Used in shell scripts and automation
- Integrated into CI/CD pipelines
- Embedded in other security tools
- Run on any Linux system with kernel 4.15+

**System Context Diagram:**

```
┌──────────────────────────────────────────────────────────┐
│                    Linux System                          │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│  │ Application│  │ Application│  │ Application│       │
│  │     A      │  │     B      │  │     C      │       │
│  │            │  │            │  │            │       │
│  │ • OpenSSL  │  │ • GnuTLS   │  │ • libsodium│       │
│  │ • cert.pem │  │ • key.pem  │  │ • keystore │       │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘       │
│        │               │               │               │
│        └───────────────┴───────────────┘               │
│                        │                               │
│                        │ syscalls, lib loads           │
│        ┌───────────────▼────────────────┐              │
│        │     Linux Kernel                │              │
│        │  ┌──────────────────────────┐  │              │
│        │  │   eBPF Programs          │  │              │
│        │  │   (loaded by crypto-    │  │              │
│        │  │    tracer)               │  │              │
│        │  │                          │  │              │
│        │  │  • File open hooks       │  │              │
│        │  │  • dlopen hooks          │  │              │
│        │  │  • Process exec hooks    │  │              │
│        │  └──────────┬───────────────┘  │              │
│        │             │ events            │              │
│        │             │                   │              │
│        │   ┌─────────▼──────────┐       │              │
│        │   │   Ring Buffer      │       │              │
│        │   └─────────┬──────────┘       │              │
│        └─────────────┼───────────────────┘              │
│                      │                                  │
│          ┌───────────▼──────────┐                       │
│          │   crypto-tracer      │                       │
│          │   (User-Space)       │                       │
│          │                      │                       │
│          │  • Event processor   │                       │
│          │  • JSON formatter    │                       │
│          │  • Privacy filter    │                       │
│          └───────────┬──────────┘                       │
│                      │                                  │
└──────────────────────┼──────────────────────────────────┘
                       │
                       │ JSON output
                       ▼
              ┌────────────────┐
              │  stdout/file   │
              │  • Live stream │
              │  • JSON events │
              │  • Summary     │
              └────────────────┘
```

**Key Characteristics:**
1. **No External Dependencies:** Self-contained, no databases, no APIs, no cloud services
2. **Stateless by Default:** Each run is independent (optional stateful mode)
3. **Unix Philosophy:** Do one thing well, output to stdout, composable with other tools
4. **Privacy-First:** No telemetry, no data collection, works fully offline

### 2.2 Product Functions

crypto-tracer provides the following major functions:

#### F1: Process Monitoring Mode
**Description:** Monitor all processes on the system for cryptographic activity

**Example Usage:**
```bash
# Monitor for 60 seconds
crypto-tracer monitor --duration 60

# Monitor continuously (until Ctrl+C)
crypto-tracer monitor

# Monitor with filters
crypto-tracer monitor --pid 1234 --library openssl
```

**Output:** Stream of JSON events showing crypto operations

#### F2: Process Profiling Mode
**Description:** Generate a detailed profile of a specific process's crypto usage

**Example Usage:**
```bash
# Profile Apache process
crypto-tracer profile --pid 1234

# Profile by process name
crypto-tracer profile --name nginx

# Profile with duration
crypto-tracer profile --pid 1234 --duration 30
```

**Output:** JSON document with complete crypto profile

#### F3: Snapshot Mode
**Description:** Quick snapshot of all current crypto activity

**Example Usage:**
```bash
# Take snapshot
crypto-tracer snapshot

# Snapshot with output to file
crypto-tracer snapshot --output /tmp/snapshot.json
```

**Output:** JSON document listing all processes using crypto

#### F4: Library Discovery Mode
**Description:** List all cryptographic libraries loaded on the system

**Example Usage:**
```bash
# Find all crypto libraries
crypto-tracer libs

# Find specific library
crypto-tracer libs --name openssl
```

**Output:** JSON list of crypto libraries and processes using them

#### F5: File Tracking Mode
**Description:** Track access to cryptographic files (certs, keys)

**Example Usage:**
```bash
# Monitor cert/key access
crypto-tracer files --duration 60

# Track specific file
crypto-tracer files --path /etc/ssl/certs/server.crt
```

**Output:** JSON stream of file access events

### 2.3 User Classes and Characteristics

#### User Class 1: Security Researchers

**Characteristics:**
- Technical expertise: Very High
- Domain knowledge: Expert in security/crypto
- Usage frequency: Daily/Weekly
- Primary tasks: Analyzing crypto behavior, finding vulnerabilities

**Needs:**
- Detailed event streams
- Raw data access
- Filtering capabilities
- Scriptable interface

**Example Workflow:**
```bash
# Research how application X handles certificates
crypto-tracer monitor --name appX --duration 300 --output research.json
# Analyze with jq or custom tools
cat research.json | jq '.events[] | select(.event_type=="file_access")'
```

#### User Class 2: System Administrators

**Characteristics:**
- Technical expertise: High
- Domain knowledge: Strong in systems, moderate in crypto
- Usage frequency: As-needed (troubleshooting)
- Primary tasks: Debugging issues, verifying configurations

**Needs:**
- Easy-to-read output
- Quick snapshots
- Process identification
- Clear error messages

**Example Workflow:**
```bash
# Why can't nginx start?
sudo crypto-tracer profile --name nginx --duration 10
# Check if it's accessing certificate files
```

#### User Class 3: DevOps Engineers

**Characteristics:**
- Technical expertise: High
- Domain knowledge: Strong in automation, moderate in crypto
- Usage frequency: During deployments
- Primary tasks: Validation, CI/CD integration

**Needs:**
- JSON output for automation
- Exit codes for scripting
- Fast execution
- Non-interactive mode

**Example Workflow:**
```bash
#!/bin/bash
# Verify application uses correct crypto libraries
crypto-tracer snapshot --output /tmp/crypto.json
if jq -e '.processes[] | select(.libraries[] | contains("libssl3"))' /tmp/crypto.json; then
  echo "✓ Using OpenSSL 3.x"
else
  echo "✗ Not using OpenSSL 3.x"
  exit 1
fi
```

#### User Class 4: Compliance Officers

**Characteristics:**
- Technical expertise: Low to Moderate
- Domain knowledge: Strong in compliance, low in technical
- Usage frequency: Monthly (audit cycles)
- Primary tasks: Generating audit reports

**Needs:**
- Simple commands
- Human-readable summaries
- Export to reports
- Documentation

**Example Workflow:**
```bash
# Generate audit evidence
sudo crypto-tracer snapshot --output audit-$(date +%Y%m%d).json
# Send to compliance team for review
```

### 2.4 Operating Environment

#### 2.4.1 Hardware Environment

**Minimum Requirements:**
- CPU: x86_64 or ARM64, 2 cores
- RAM: 512MB available
- Disk: 50MB for tool + 100MB for logs/output
- Network: Not required (offline operation)

**Recommended Requirements:**
- CPU: 4+ cores (for high-throughput monitoring)
- RAM: 2GB available
- Disk: 1GB for extended monitoring sessions
- SSD: Preferred for high-frequency event logging

**Supported Architectures:**
- x86_64 (Intel, AMD) - Tier 1 support
- ARM64 (AWS Graviton, Ampere, Raspberry Pi 4) - Tier 1 support
- Other architectures - Best effort (community contributions)

#### 2.4.2 Software Environment

**Operating Systems (Linux-only):**

| Distribution | Version | Kernel | Support Level |
|--------------|---------|--------|---------------|
| Ubuntu LTS | 20.04+ | 5.4+ | Tier 1 |
| Ubuntu | 22.04+ | 5.15+ | Tier 1 |
| Debian | 11+ | 5.10+ | Tier 1 |
| RHEL | 8+ | 4.18+ | Tier 1 |
| RHEL | 9+ | 5.14+ | Tier 1 |
| Amazon Linux | 2023 | 6.1+ | Tier 1 |
| Fedora | 37+ | 6.0+ | Tier 2 |
| Alpine Linux | 3.17+ | 5.15+ | Tier 2 |

**Required Kernel Features:**
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y (recommended for CO-RE)
CONFIG_TRACEPOINTS=y
CONFIG_KPROBES=y
CONFIG_UPROBES=y
```

**Runtime Dependencies:**
- glibc 2.31+ (or musl for Alpine)
- libelf 0.186+
- zlib 1.2.11+

**Kernel Capabilities Required:**
- CAP_BPF (kernel 5.8+) OR CAP_SYS_ADMIN (older kernels)
- CAP_PERFMON (optional, for enhanced tracing)
- Alternatively: Run as root (not recommended but supported)

**No Other Dependencies:**
- No Python, Ruby, Node.js, or other language runtimes required
- No database systems required
- No web servers required
- No configuration management systems required

#### 2.4.3 Development Environment

**Build Requirements:**
- GCC 10+ or Clang 11+
- GNU Make 4.0+
- Linux kernel headers (matching target kernel)
- libbpf-dev 0.6.0+
- libelf-dev
- zlib1g-dev
- Clang with BPF backend (for eBPF compilation)

**Optional Build Tools:**
- CMake 3.16+ (alternative build system)
- Doxygen (for documentation generation)
- cJSON library (for JSON generation, or embed single-header)

### 2.5 Design and Implementation Constraints

#### 2.5.1 Technical Constraints

**eBPF Limitations:**
- Maximum 1 million BPF instructions per program
- Stack size limited to 512 bytes per program
- No floating point operations
- No unbounded loops (must be verifiable)
- Limited kernel memory access (only via helper functions)

**Linux Kernel Compatibility:**
- Must support kernels 4.15 (minimum) through 6.x (current)
- Use BPF CO-RE for portability
- Graceful feature degradation on older kernels
- No kernel-specific hacks or workarounds

**Single Binary Constraint:**
- All eBPF programs embedded in binary (skeleton code)
- All resources embedded (no external files at runtime)
- Static linking preferred for distribution
- Binary size target: <10MB

#### 2.5.2 Resource Constraints

**Memory:**
- User-space resident memory: <50MB
- Kernel-space BPF maps: <10MB
- Event buffer size: 1MB (configurable)

**CPU:**
- Overhead: <0.5% average per core
- Peak overhead: <2% per core
- No busy-waiting (event-driven architecture)

**Disk:**
- No persistent state by default
- Optional: Event log up to 1GB (user-configurable)

#### 2.5.3 Security Constraints

**Privilege Requirements:**
- Requires CAP_BPF or root for eBPF loading
- Must validate privileges at startup
- Must drop unnecessary privileges after BPF load
- No setuid binaries (use sudo or capabilities)

**Privacy Requirements:**
- No private key content ever logged
- No plaintext passwords in output
- Path redaction by default
- Configurable privacy levels

**Safety Requirements:**
- Read-only operation (no system modifications)
- Must pass kernel BPF verifier
- No kernel crashes or panics
- Graceful failure (no data corruption)

#### 2.5.4 Portability Constraints

**Cross-Kernel Portability:**
- Use BPF CO-RE (Compile Once, Run Everywhere)
- Include BTF information in binary
- Runtime kernel feature detection
- Conditional feature enablement

**Cross-Distribution Portability:**
- Standard Linux APIs only
- No distribution-specific paths or configs
- Detect paths at runtime (/proc, /sys)
- Work on glibc and musl

#### 2.5.5 Development Constraints

**Open Source Requirements:**
- MIT or Apache-2.0 license
- All dependencies permissively licensed (no GPL in core)
- Well-documented code
- Contribution guidelines

**Code Quality:**
- C11 standard compliance
- Compiler warnings as errors (-Werror)
- Static analysis (clang-tidy, cppcheck)
- Memory safety (no leaks, no use-after-free)

### 2.6 Assumptions and Dependencies

#### 2.6.1 Assumptions

**System Assumptions:**
1. Target system runs Linux kernel 4.15 or higher
2. eBPF is enabled in kernel (CONFIG_BPF=y)
3. System has root or CAP_BPF capability available
4. /proc and /sys filesystems are mounted
5. System has at least 512MB free RAM

**Usage Assumptions:**
1. User understands basic Linux command-line usage
2. User has sudo access if not running as root
3. Monitored applications use standard crypto libraries (OpenSSL, GnuTLS, etc.)
4. Crypto files use standard naming (.pem, .crt, .key, .p12)

**Operational Assumptions:**
1. System clock is reasonably accurate (for timestamps)
2. Monitored processes are not malicious (no anti-debugging)
3. File system paths are accessible (permissions)
4. Kernel is not actively hostile to eBPF programs

#### 2.6.2 Dependencies

**Build-Time Dependencies:**

| Dependency | Version | Purpose | License |
|------------|---------|---------|---------|
| GCC or Clang | 10+/11+ | Compiler | GPL-3.0 / Apache-2.0 |
| libbpf | 0.6.0+ | eBPF loading | LGPL-2.1 OR BSD-2-Clause |
| libelf | 0.186+ | ELF parsing | LGPL-3.0+ |
| zlib | 1.2.11+ | Compression | Zlib |
| Linux headers | Matching kernel | BPF compilation | GPL-2.0 |
| cJSON (optional) | 1.7.15+ | JSON generation | MIT |

**Runtime Dependencies:**

| Dependency | Version | Purpose | License |
|------------|---------|---------|---------|
| glibc or musl | 2.31+/1.2.3+ | C library | LGPL-2.1+ / MIT |
| libelf | 0.186+ | ELF parsing | LGPL-3.0+ |
| zlib | 1.2.11+ | Compression | Zlib |

**No External Service Dependencies:**
- No cloud services
- No external APIs
- No licensing servers
- No telemetry endpoints
- No update servers

**Optional Dependencies (Compile-Time Flags):**
- Systemd integration: libsystemd (for journal logging)
- Static linking: musl-gcc (for fully static binaries)

---

## 3. Specific Requirements

This section details the specific functional requirements for crypto-tracer. Requirements are tagged with unique identifiers and priority levels.

**Priority Levels:**
- **P0 (Critical):** Must-have for MVP, blocks release
- **P1 (High):** Important for v1.0, should not defer
- **P2 (Medium):** Valuable but can defer to v1.1
- **P3 (Low):** Nice-to-have, future consideration

---

### 3.1 Functional Requirements

#### 3.1.1 Command-Line Interface

**REQ-CLI-001: Monitor Command** [P0]

**Description:** The tool shall provide a `monitor` command for continuous monitoring.

**Syntax:**
```bash
crypto-tracer monitor [OPTIONS]
```

**Options:**
- `--duration SECONDS` - Monitor for specified duration (0=infinite, default: infinite)
- `--output FILE` - Write output to file instead of stdout
- `--format FORMAT` - Output format: json-stream (default), json-lines, json-array
- `--pid PID` - Monitor only specified process ID
- `--name NAME` - Monitor only processes matching name
- `--library LIB` - Filter events related to specific library
- `--file PATH` - Filter events related to specific file
- `--verbose` - Enable verbose output (debug mode)
- `--quiet` - Suppress informational messages
- `--no-redact` - Disable path redaction (show full paths)

**Behavior:**
1. Load eBPF programs into kernel
2. Begin monitoring system activity
3. Stream events to output as they occur
4. Continue until duration expires or SIGINT (Ctrl+C)
5. Clean up eBPF programs on exit

**Output:** JSON stream of crypto events

**Exit Codes:**
- 0: Success
- 1: General error
- 2: Invalid arguments
- 3: Insufficient privileges
- 4: Kernel not supported
- 130: Interrupted by user (SIGINT)

**Examples:**
```bash
# Monitor for 60 seconds
sudo crypto-tracer monitor --duration 60

# Monitor nginx processes only
sudo crypto-tracer monitor --name nginx

# Monitor and save to file
sudo crypto-tracer monitor --duration 300 --output /tmp/crypto.json
```

**Acceptance Criteria:**
1. Command parses all options correctly
2. Validates arguments before starting
3. Loads eBPF programs successfully
4. Outputs JSON events in real-time
5. Handles SIGINT gracefully (clean shutdown)
6. Unloads eBPF programs on exit
7. Returns appropriate exit codes

**Test Cases:**
- TC-CLI-001-1: Run with no options (infinite monitoring)
- TC-CLI-001-2: Run with --duration 10
- TC-CLI-001-3: Run with --pid filter
- TC-CLI-001-4: Run with --output file
- TC-CLI-001-5: Ctrl+C during monitoring (clean exit)
- TC-CLI-001-6: Invalid option (should error)
- TC-CLI-001-7: Run without privileges (should error)

---

**REQ-CLI-002: Profile Command** [P0]

**Description:** The tool shall provide a `profile` command to generate a detailed profile of a process.

**Syntax:**
```bash
crypto-tracer profile [OPTIONS]
```

**Options:**
- `--pid PID` - Profile specific process ID (required if --name not given)
- `--name NAME` - Profile processes matching name (required if --pid not given)
- `--duration SECONDS` - Profile duration (default: 30 seconds)
- `--output FILE` - Write output to file instead of stdout
- `--format FORMAT` - Output format: json (default), json-pretty
- `--follow-children` - Include child processes in profile
- `--no-redact` - Disable path redaction

**Behavior:**
1. Identify target process(es)
2. Attach eBPF programs specific to target
3. Collect events for specified duration
4. Aggregate events into profile document
5. Output complete profile as JSON

**Output:** JSON document with process profile

**Example Output Structure:**
```json
{
  "profile_version": "1.0",
  "generated_at": "2025-11-17T10:30:00Z",
  "duration_seconds": 30,
  "process": {
    "pid": 1234,
    "name": "nginx",
    "exe": "/usr/sbin/nginx",
    "cmdline": "nginx -g daemon off;",
    "uid": 0,
    "gid": 0,
    "start_time": "2025-11-17T10:00:00Z"
  },
  "libraries": [
    {
      "name": "libssl.so.3",
      "path": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
      "load_time": "2025-11-17T10:00:01Z"
    }
  ],
  "files_accessed": [
    {
      "path": "/etc/ssl/certs/server.crt",
      "type": "certificate",
      "access_count": 1,
      "first_access": "2025-11-17T10:00:02Z",
      "last_access": "2025-11-17T10:00:02Z",
      "mode": "read"
    }
  ],
  "api_calls": {
    "SSL_CTX_new": 1,
    "SSL_accept": 45
  },
  "statistics": {
    "total_events": 100,
    "libraries_loaded": 2,
    "files_accessed": 3,
    "api_calls_made": 46
  }
}
```

**Acceptance Criteria:**
1. Profiles target process for specified duration
2. Aggregates all crypto-related events
3. Outputs complete JSON profile
4. Handles non-existent PID gracefully
5. Handles process that exits during profiling
6. Includes child processes if --follow-children

**Test Cases:**
- TC-CLI-002-1: Profile nginx by PID
- TC-CLI-002-2: Profile by name (multiple matches)
- TC-CLI-002-3: Profile with --follow-children
- TC-CLI-002-4: Profile process that exits early
- TC-CLI-002-5: Profile non-existent PID (error)

---

**REQ-CLI-003: Snapshot Command** [P0]

**Description:** The tool shall provide a `snapshot` command for quick system-wide crypto inventory.

**Syntax:**
```bash
crypto-tracer snapshot [OPTIONS]
```

**Options:**
- `--output FILE` - Write output to file instead of stdout
- `--format FORMAT` - Output format: json (default), json-pretty, summary
- `--no-redact` - Disable path redaction

**Behavior:**
1. Quickly scan all running processes
2. Identify which processes have crypto libraries loaded
3. Check which processes have crypto files open (from /proc/[pid]/fd)
4. Generate snapshot document

**Output:** JSON document listing all processes using crypto

**Example Output:**
```json
{
  "snapshot_version": "1.0",
  "generated_at": "2025-11-17T10:30:00Z",
  "hostname": "web-server-01",
  "kernel": "5.15.0-76-generic",
  "processes": [
    {
      "pid": 1234,
      "name": "nginx",
      "exe": "/usr/sbin/nginx",
      "libraries": ["libssl.so.3"],
      "open_crypto_files": ["/etc/ssl/certs/server.crt"],
      "running_as": "root"
    },
    {
      "pid": 5678,
      "name": "postgres",
      "exe": "/usr/lib/postgresql/14/bin/postgres",
      "libraries": ["libssl.so.1.1"],
      "open_crypto_files": ["/var/lib/postgresql/server.crt", "/var/lib/postgresql/server.key"],
      "running_as": "postgres"
    }
  ],
  "summary": {
    "total_processes": 2,
    "total_libraries": 2,
    "total_files": 3
  }
}
```

**Acceptance Criteria:**
1. Scans all processes quickly (<5 seconds)
2. Identifies crypto library usage from /proc/[pid]/maps
3. Lists open crypto files from /proc/[pid]/fd
4. Outputs complete snapshot document
5. Works without eBPF (uses /proc only)

**Test Cases:**
- TC-CLI-003-1: Take snapshot on idle system
- TC-CLI-003-2: Take snapshot on busy system (100+ processes)
- TC-CLI-003-3: Verify summary statistics correct
- TC-CLI-003-4: Snapshot with --format summary (human-readable)

---

**REQ-CLI-004: Version and Help Commands** [P0]

**Description:** The tool shall provide `--version` and `--help` options.

**Syntax:**
```bash
crypto-tracer --version
crypto-tracer --help
crypto-tracer COMMAND --help
```

**Behavior:**
- `--version`: Print version number and exit
- `--help`: Print usage information and exit
- `COMMAND --help`: Print help for specific command

**Version Output:**
```
crypto-tracer version 1.0.0
Built: 2025-11-17
Kernel support: 4.15+
eBPF: libbpf 0.8.0
License: MIT
```

**Help Output:**
```
crypto-tracer - Runtime cryptographic behavior analysis

USAGE:
    crypto-tracer <COMMAND> [OPTIONS]

COMMANDS:
    monitor     Monitor system for crypto activity
    profile     Profile a specific process
    snapshot    Take system snapshot
    libs        List loaded crypto libraries
    files       Track crypto file access
    version     Print version information
    help        Print this help message

OPTIONS:
    --help      Print help information
    --version   Print version information

For more information on a specific command:
    crypto-tracer COMMAND --help

Examples:
    crypto-tracer monitor --duration 60
    crypto-tracer profile --pid 1234
    crypto-tracer snapshot --output snapshot.json
```

**Acceptance Criteria:**
1. --version prints version and exits with code 0
2. --help prints usage and exits with code 0
3. Invalid command shows error and suggests --help
4. Help text is clear and accurate

---

#### 3.1.2 eBPF Program Management

**REQ-BPF-001: eBPF Program Loading** [P0]

**Description:** The tool shall load and attach eBPF programs to monitor crypto operations.

**eBPF Programs to Load:**

1. **file_open_trace.bpf.c** - Tracepoint on sys_enter_open/openat
   - Monitors file open operations
   - Filters for crypto file extensions (.pem, .crt, .key, .p12, .pfx, .jks, .keystore)
   - Records: PID, filename, flags, timestamp

2. **lib_load_trace.bpf.c** - Uprobe on dlopen()
   - Monitors dynamic library loading
   - Filters for crypto library names (libssl, libcrypto, libgnutls, libsodium, etc.)
   - Records: PID, library path, timestamp

3. **process_exec_trace.bpf.c** - Tracepoint on sched_process_exec
   - Monitors process execution
   - Records: PID, PPID, process name, command line (truncated)
   - Enables process tree construction

4. **process_exit_trace.bpf.c** - Tracepoint on sched_process_exit
   - Monitors process termination
   - Records: PID, exit code, timestamp
   - Enables cleanup of tracking data

5. **openssl_api_trace.bpf.c** (Optional, P1) - Uprobes on OpenSSL functions
   - Monitors SSL_CTX_new, SSL_connect, SSL_accept
   - Records: PID, function name, timestamp
   - Not loaded if OpenSSL not detected

**Loading Sequence:**
1. Check kernel version and capabilities
2. Verify BPF is enabled in kernel
3. Load BPF skeleton code (embedded in binary)
4. Attach to tracepoints (file, process)
5. Attach to uprobes (dlopen, OpenSSL if available)
6. Verify all programs loaded successfully
7. Set up ring buffer for event communication

**Error Handling:**
- If privilege check fails → Exit with error code 3
- If kernel too old → Exit with error code 4 and suggest upgrade
- If BPF verifier rejects → Log verifier output, exit with error
- If partial load (some programs fail) → Log warning, continue with reduced functionality

**Acceptance Criteria:**
1. All eBPF programs load successfully on supported kernels
2. Programs pass kernel verifier
3. Programs attach to correct hook points
4. Ring buffer created for event passing
5. Graceful degradation if optional programs fail
6. Clear error messages for failures

**Test Cases:**
- TC-BPF-001-1: Load on kernel 5.15 (should succeed)
- TC-BPF-001-2: Load on kernel 4.15 (minimal features)
- TC-BPF-001-3: Load on kernel 6.1 (all features)
- TC-BPF-001-4: Load without CAP_BPF (should fail)
- TC-BPF-001-5: Verify programs attached (bpftool list)

---

**REQ-BPF-002: eBPF Program Unloading** [P0]

**Description:** The tool shall cleanly unload eBPF programs on exit.

**Unloading Sequence:**
1. Detach all programs from hook points
2. Close ring buffer
3. Unload all BPF programs from kernel
4. Free all BPF maps
5. Release all resources

**Trigger Conditions:**
- Normal exit (duration expired)
- SIGINT (Ctrl+C)
- SIGTERM
- Error condition requiring shutdown

**Timeout:**
- Unload must complete within 5 seconds
- If timeout, force-kill and log warning

**Acceptance Criteria:**
1. All BPF programs detached and unloaded
2. All BPF maps freed
3. No kernel resources leaked
4. Unload completes within 5 seconds
5. Handles multiple signals gracefully

**Test Cases:**
- TC-BPF-002-1: Normal exit after duration
- TC-BPF-002-2: Exit via Ctrl+C
- TC-BPF-002-3: Exit via SIGTERM
- TC-BPF-002-4: Verify no leaked resources (bpftool list)
- TC-BPF-002-5: Rapid start/stop cycles

---

#### 3.1.3 Event Processing

**REQ-EVENT-001: Event Collection** [P0]

**Description:** The tool shall collect events from eBPF ring buffer with low latency.

**Event Types:**

1. **file_open** - File open operation
```c
struct file_open_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t uid;
    char filename[256];
    uint32_t flags;
    char comm[16];  // process name
};
```

2. **lib_load** - Library loaded
```c
struct lib_load_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t uid;
    char lib_path[256];
    char comm[16];
};
```

3. **process_exec** - Process started
```c
struct process_exec_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char comm[16];
    char cmdline[256];
};
```

4. **process_exit** - Process exited
```c
struct process_exit_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    int32_t exit_code;
};
```

5. **api_call** (Optional, P1) - Crypto API called
```c
struct api_call_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    char function_name[64];
    char library[64];
};
```

**Collection Behavior:**
- Poll ring buffer every 10ms (configurable)
- Batch process events for efficiency (up to 100 events per batch)
- Event processing latency: <50ms (99th percentile)
- No event loss under normal load (<5,000 events/sec)
- Backpressure if user-space can't keep up (log warning)

**Acceptance Criteria:**
1. Successfully collects all event types
2. Latency <50ms for 99% of events
3. No event loss at 5,000 events/sec
4. Handles ring buffer overrun gracefully
5. Batch processing for efficiency

**Test Cases:**
- TC-EVENT-001-1: Collect 100 events (low rate)
- TC-EVENT-001-2: Collect 5,000 events/sec (normal)
- TC-EVENT-001-3: Collect 20,000 events/sec (stress, may drop)
- TC-EVENT-001-4: Verify event ordering preserved
- TC-EVENT-001-5: Handle ring buffer full condition

---

**REQ-EVENT-002: Event Filtering** [P1]

**Description:** The tool shall filter events based on command-line options.

**Filter Types:**

1. **PID Filter** (`--pid PID`)
   - Only process events from specified PID
   - Implemented in user-space (not kernel, for simplicity)

2. **Process Name Filter** (`--name NAME`)
   - Only process events from processes matching name
   - Supports substring matching (case-insensitive)

3. **Library Filter** (`--library LIB`)
   - Only process lib_load events for specified library
   - Supports substring matching

4. **File Filter** (`--file PATH`)
   - Only process file_open events for specified path
   - Supports glob patterns (*, ?)

**Filter Evaluation:**
- Filters are AND-ed together (all must match)
- Applied to each event before output
- Non-matching events silently dropped
- Filter overhead: <1 microsecond per event

**Acceptance Criteria:**
1. PID filter works correctly
2. Name filter matches correctly (case-insensitive)
3. Library filter matches substring
4. File filter supports glob patterns
5. Multiple filters combine with AND logic
6. Minimal performance impact (<1μs per event)

**Test Cases:**
- TC-EVENT-002-1: Filter by PID
- TC-EVENT-002-2: Filter by name (substring)
- TC-EVENT-002-3: Filter by library
- TC-EVENT-002-4: Filter by file (glob pattern)
- TC-EVENT-002-5: Multiple filters combined

---

**REQ-EVENT-003: Event Formatting** [P0]

**Description:** The tool shall format events as JSON for output.

**JSON Event Format:**

**file_open event:**
```json
{
  "event_type": "file_open",
  "timestamp": "2025-11-17T10:30:45.123456Z",
  "pid": 1234,
  "uid": 0,
  "process": "nginx",
  "file": "/etc/ssl/certs/server.crt",
  "flags": "O_RDONLY",
  "file_type": "certificate"
}
```

**lib_load event:**
```json
{
  "event_type": "lib_load",
  "timestamp": "2025-11-17T10:30:45.234567Z",
  "pid": 1234,
  "uid": 0,
  "process": "nginx",
  "library": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
  "library_name": "libssl.so.3"
}
```

**process_exec event:**
```json
{
  "event_type": "process_exec",
  "timestamp": "2025-11-17T10:30:44.123456Z",
  "pid": 1234,
  "ppid": 1,
  "uid": 0,
  "process": "nginx",
  "cmdline": "nginx -g daemon off;"
}
```

**process_exit event:**
```json
{
  "event_type": "process_exit",
  "timestamp": "2025-11-17T10:35:45.123456Z",
  "pid": 1234,
  "exit_code": 0
}
```

**Output Formats:**

1. **json-stream** (default) - One JSON object per line, no array wrapper
```
{"event_type": "file_open", ...}
{"event_type": "lib_load", ...}
{"event_type": "process_exec", ...}
```

2. **json-lines** - Same as json-stream (alias)

3. **json-array** - JSON array of events
```json
[
  {"event_type": "file_open", ...},
  {"event_type": "lib_load", ...},
  {"event_type": "process_exec", ...}
]
```

**Acceptance Criteria:**
1. All events formatted as valid JSON
2. Timestamps in ISO 8601 format with microsecond precision
3. All fields present and correctly typed
4. json-stream output is streamable (no array wrapper)
5. json-array output is valid JSON array

**Test Cases:**
- TC-EVENT-003-1: Parse json-stream output with jq
- TC-EVENT-003-2: Parse json-array output with jq
- TC-EVENT-003-3: Validate timestamps (ISO 8601)
- TC-EVENT-003-4: Verify all fields present
- TC-EVENT-003-5: Handle special characters in strings

---

#### 3.1.4 Privacy and Security

**REQ-PRIVACY-001: Path Redaction** [P0]

**Description:** The tool shall redact sensitive information from file paths by default.

**Redaction Rules:**

1. **Home Directory Redaction**
   - `/home/username/` → `/home/USER/`
   - `/root/` → `/home/ROOT/`

2. **Username Removal**
   - `/var/lib/docker/volumes/username_data/` → `/var/lib/docker/volumes/USERID_data/`

3. **Preserve System Paths**
   - `/etc/`, `/usr/`, `/lib/`, `/var/lib/` - No redaction
   - System-wide paths are not considered sensitive

**Examples:**
```
Original: /home/john/app/certs/server.crt
Redacted: /home/USER/app/certs/server.crt

Original: /root/.ssh/id_rsa
Redacted: /home/ROOT/.ssh/id_rsa

Original: /etc/ssl/certs/ca-certificates.crt
Redacted: /etc/ssl/certs/ca-certificates.crt (no change)
```

**Bypass:**
- `--no-redact` flag disables all redaction
- Useful for debugging or when privacy not a concern

**Acceptance Criteria:**
1. Home directories redacted by default
2. System paths not redacted
3. Redaction applied to all path fields
4. --no-redact disables all redaction
5. No performance impact (simple string replacement)

**Test Cases:**
- TC-PRIVACY-001-1: Redact /home/user/ path
- TC-PRIVACY-001-2: Don't redact /etc/ path
- TC-PRIVACY-001-3: Redact /root/ path
- TC-PRIVACY-001-4: --no-redact shows full paths
- TC-PRIVACY-001-5: Verify no PII in default output

---

**REQ-PRIVACY-002: No Sensitive Data Logging** [P0]

**Description:** The tool shall never log or output sensitive cryptographic data.

**Prohibited Data:**
- Private key content (PEM, DER data)
- Passwords or passphrases
- API keys or tokens
- Plaintext data being encrypted
- Cryptographic operation results (ciphertexts, signatures)

**Allowed Data:**
- File paths (after redaction)
- Library names and versions
- API function names
- Timestamps
- Process metadata (PID, name, UID)
- Open flags and modes

**Verification:**
- Code review of all output paths
- Grep for suspicious patterns in source
- Penetration testing for data leaks

**Acceptance Criteria:**
1. No private key content in any output
2. No passwords in logs or JSON
3. No plaintext data from applications
4. Only metadata logged (filenames, function names)
5. Privacy audit passes

**Test Cases:**
- TC-PRIVACY-002-1: Monitor app opening private key (only filename logged)
- TC-PRIVACY-002-2: Review all JSON output for sensitive data
- TC-PRIVACY-002-3: Fuzz test with crafted inputs
- TC-PRIVACY-002-4: Code review checklist passed

---

**REQ-SECURITY-001: Privilege Validation** [P0]

**Description:** The tool shall validate required privileges at startup and fail fast if insufficient.

**Required Capabilities:**
- CAP_BPF (kernel 5.8+) OR
- CAP_SYS_ADMIN (kernel <5.8) OR
- Running as root (UID 0)

**Validation Sequence:**
1. Check effective UID (geteuid())
2. If not root, check for CAP_BPF/CAP_SYS_ADMIN (capget())
3. If insufficient privileges:
   - Print clear error message
   - Explain how to grant capabilities
   - Exit with code 3

**Error Message Example:**
```
Error: Insufficient privileges to load eBPF programs

crypto-tracer requires CAP_BPF or CAP_SYS_ADMIN capability.

Solutions:
  1. Run with sudo:
     sudo crypto-tracer monitor

  2. Grant capability (recommended):
     sudo setcap cap_bpf+ep /usr/local/bin/crypto-tracer

  3. Grant CAP_SYS_ADMIN (older kernels):
     sudo setcap cap_sys_admin+ep /usr/local/bin/crypto-tracer

For more information: https://github.com/yourusername/crypto-tracer/docs/privileges.md
```

**Acceptance Criteria:**
1. Validates privileges before loading BPF
2. Detects CAP_BPF on kernel 5.8+
3. Falls back to CAP_SYS_ADMIN on older kernels
4. Accepts root UID as sufficient
5. Provides helpful error message
6. Exits with code 3 if insufficient

**Test Cases:**
- TC-SECURITY-001-1: Run as root (should succeed)
- TC-SECURITY-001-2: Run with CAP_BPF (should succeed)
- TC-SECURITY-001-3: Run with CAP_SYS_ADMIN (should succeed)
- TC-SECURITY-001-4: Run as normal user (should fail with error)
- TC-SECURITY-001-5: Verify error message helpful

---

**REQ-SECURITY-002: Read-Only Operation** [P0]

**Description:** The tool shall operate in read-only mode with no system modifications.

**Read-Only Guarantees:**
- No files created (except output file if specified)
- No files modified
- No processes killed or modified
- No system configuration changed
- No persistent state stored (by default)

**Allowed Operations:**
- Read /proc filesystem
- Read /sys filesystem
- Load eBPF programs (temporary, kernel-managed)
- Write to stdout or specified output file
- Create temporary memory structures

**Safety:**
- eBPF programs are read-only (observe only)
- No eBPF maps shared with applications
- No interference with monitored processes

**Acceptance Criteria:**
1. No files created except output file
2. No files modified in any way
3. Monitored applications unaffected
4. eBPF programs are safe (pass verifier)
5. No persistent changes to system

**Test Cases:**
- TC-SECURITY-002-1: Monitor system, verify no new files (find /)
- TC-SECURITY-002-2: Verify application performance unchanged
- TC-SECURITY-002-3: eBPF programs pass verifier
- TC-SECURITY-002-4: No /var, /etc modifications
- TC-SECURITY-002-5: Tool crash doesn't affect system

---

#### 3.1.5 Performance and Resource Management

**REQ-PERF-001: Low CPU Overhead** [P0]

**Description:** The tool shall maintain minimal CPU overhead during monitoring.

**Performance Targets:**
- Average CPU usage: <0.5% per core
- Peak CPU usage: <2% per core (during event bursts)
- No impact on monitored applications (>99% of baseline performance)

**Measurement Method:**
- Use `top`, `htop`, or `/proc/[pid]/stat` to measure CPU usage
- Baseline: Measure monitored application performance without tool
- With tool: Measure with tool running
- Compare: Difference should be <1%

**Optimization Strategies:**
- Event batching (process multiple events per iteration)
- Efficient filtering (drop non-matching events early)
- Minimal memory allocation (reuse buffers)
- No unnecessary syscalls

**Acceptance Criteria:**
1. CPU usage <0.5% average
2. CPU usage <2% peak
3. Application performance impact <1%
4. Scales with number of cores (multi-core friendly)

**Test Cases:**
- TC-PERF-001-1: Monitor idle system (CPU usage)
- TC-PERF-001-2: Monitor high-traffic web server
- TC-PERF-001-3: Monitor database with heavy load
- TC-PERF-001-4: 24-hour stability test
- TC-PERF-001-5: Multi-core scaling

---

**REQ-PERF-002: Low Memory Footprint** [P0]

**Description:** The tool shall use minimal memory.

**Memory Targets:**
- Resident memory (RSS): <50MB
- Virtual memory (VSZ): <100MB
- No memory leaks (stable over time)
- BPF maps: <5MB

**Measurement Method:**
- Use `ps aux`, `smem`, or `/proc/[pid]/status`
- Monitor RSS and VSZ
- Run for extended period, verify no growth

**Memory Management:**
- Preallocate buffers (avoid runtime allocation)
- Reuse event structures
- Limit event buffer size (1MB max)
- Free resources promptly

**Acceptance Criteria:**
1. RSS <50MB average
2. No memory leaks (valgrind clean)
3. Memory stable over time
4. BPF maps <5MB

**Test Cases:**
- TC-PERF-002-1: Memory at startup
- TC-PERF-002-2: Memory after 1 hour
- TC-PERF-002-3: Memory after 24 hours
- TC-PERF-002-4: Valgrind memcheck (no leaks)
- TC-PERF-002-5: Memory under high event rate

---

**REQ-PERF-003: Fast Startup** [P1]

**Description:** The tool shall start quickly.

**Startup Time Target:** <2 seconds

**Startup Sequence:**
1. Parse command-line arguments (<0.1s)
2. Validate privileges (<0.1s)
3. Load eBPF programs (<1s)
4. Attach to hook points (<0.5s)
5. Initialize ring buffer (<0.1s)
6. Ready to monitor

**Acceptance Criteria:**
1. Startup completes in <2 seconds
2. First event captured within 2 seconds
3. No unnecessary delays
4. Fast argument parsing

**Test Cases:**
- TC-PERF-003-1: Measure time to first event
- TC-PERF-003-2: Cold start (no cache)
- TC-PERF-003-3: Warm start (repeat runs)
- TC-PERF-003-4: Verify <2 second startup

---

#### 3.1.6 Reliability and Error Handling

**REQ-RELIABLE-001: Graceful Degradation** [P1]

**Description:** The tool shall continue operating with reduced functionality when non-critical failures occur.

**Failure Scenarios:**

1. **One eBPF program fails to load**
   - Continue with other programs
   - Log warning
   - Provide partial monitoring

2. **/proc access fails for one process**
   - Skip that process
   - Continue monitoring others
   - Log warning

3. **Event parsing fails**
   - Log error
   - Skip event
   - Continue processing

4. **Output file write fails**
   - Log error
   - Fall back to stdout
   - Continue monitoring

**Critical Failures (Exit Required):**
- All eBPF programs fail to load
- Insufficient privileges
- Kernel not supported
- Signal received (SIGINT, SIGTERM)

**Acceptance Criteria:**
1. Continues operating on non-critical failures
2. Logs all errors and warnings
3. Provides best-effort monitoring
4. Exits only on critical failures

**Test Cases:**
- TC-RELIABLE-001-1: Fail to attach one uprobe (continue with others)
- TC-RELIABLE-001-2: /proc access denied for one PID
- TC-RELIABLE-001-3: Malformed event from kernel (skip it)
- TC-RELIABLE-001-4: Output file becomes full (fall back to stdout)

---

**REQ-RELIABLE-002: Clean Shutdown** [P0]

**Description:** The tool shall perform clean shutdown on termination signals.

**Handled Signals:**
- SIGINT (Ctrl+C)
- SIGTERM (systemctl stop, kill)
- SIGQUIT (optional, for debugging)

**Shutdown Sequence:**
1. Stop accepting new events
2. Process remaining events in buffer (up to 1 second)
3. Close output file if open
4. Unload eBPF programs
5. Free all memory
6. Exit with appropriate code

**Timeout:**
- Shutdown must complete within 5 seconds
- If timeout, force exit

**Acceptance Criteria:**
1. Handles SIGINT cleanly
2. Handles SIGTERM cleanly
3. Processes buffered events before exit
4. Unloads eBPF programs
5. Completes within 5 seconds

**Test Cases:**
- TC-RELIABLE-002-1: Ctrl+C during monitoring
- TC-RELIABLE-002-2: SIGTERM during monitoring
- TC-RELIABLE-002-3: Verify buffered events processed
- TC-RELIABLE-002-4: Verify BPF cleanup (bpftool list)
- TC-RELIABLE-002-5: Rapid signals (signal storm)

---

**REQ-RELIABLE-003: Error Reporting** [P1]

**Description:** The tool shall provide clear, actionable error messages.

**Error Message Format:**
```
Error: <Short description>

<Detailed explanation>

<Suggested action>

For more information: <URL to documentation>
```

**Examples:**

**Insufficient privileges:**
```
Error: Insufficient privileges to load eBPF programs

crypto-tracer requires CAP_BPF or CAP_SYS_ADMIN capability to load
eBPF programs into the kernel for monitoring.

Solution: Run with sudo or grant capability:
  sudo crypto-tracer monitor
  OR
  sudo setcap cap_bpf+ep /usr/local/bin/crypto-tracer

For more information:
  https://github.com/user/crypto-tracer/docs/privileges.md
```

**Kernel not supported:**
```
Error: Kernel version not supported

Detected kernel: 4.14.0 (released 2017)
Minimum required: 4.15.0 (released 2018)

crypto-tracer requires eBPF features introduced in kernel 4.15.

Solution: Upgrade kernel to 4.15 or later:
  - Ubuntu 18.04+ (kernel 4.15+)
  - Debian 10+ (kernel 4.19+)
  - RHEL 8+ (kernel 4.18+)

For more information:
  https://github.com/user/crypto-tracer/docs/requirements.md
```

**Acceptance Criteria:**
1. All errors have clear messages
2. Messages explain what went wrong
3. Messages suggest solutions
4. Include documentation links where appropriate
5. Appropriate exit codes

**Test Cases:**
- TC-RELIABLE-003-1: Trigger privilege error (verify message)
- TC-RELIABLE-003-2: Simulate old kernel (verify message)
- TC-RELIABLE-003-3: Invalid argument (verify message)
- TC-RELIABLE-003-4: File write error (verify message)

---

### 3.2 Data Requirements

#### 3.2.1 Event Data

**Event Storage:**
- Events stored in memory ring buffer (1MB, circular)
- Optional: Events written to output file (user-specified)
- No persistent storage by default

**Event Retention:**
- In-memory: Only current buffer contents (last ~10,000 events)
- File output: Until file closed or disk full
- No automatic rotation or cleanup

**Event Ordering:**
- Events ordered by timestamp (kernel time)
- Monotonic clock used (unaffected by time adjustments)
- Microsecond precision

#### 3.2.2 Process Profiles

**Profile Storage:**
- Profiles built in memory during monitoring
- Discarded on tool exit (unless output to file)
- No database or persistent storage

**Profile Data Structure:**
- Per-process profile (map by PID)
- Includes: libraries, files, API calls, statistics
- Limited to 1,000 active processes (configurable)

---

## 4. System Features

This section describes the major features using practical use case scenarios.

### Feature 1: Quick Crypto Inventory

**Priority:** P0

**Description:** System administrators can quickly identify all processes using cryptography.

#### 4.1.1 Use Case: Daily Crypto Audit

**Actor:** System Administrator

**Preconditions:**
- Administrator has sudo access
- System is running normally

**Main Flow:**
1. Administrator runs: `sudo crypto-tracer snapshot`
2. Tool scans all running processes (reads /proc)
3. Tool identifies processes with crypto libraries loaded
4. Tool identifies processes with crypto files open
5. Tool outputs JSON snapshot to stdout
6. Administrator reviews output or saves to file

**Example Output:**
```json
{
  "snapshot_version": "1.0",
  "generated_at": "2025-11-17T15:30:00Z",
  "hostname": "prod-web-01",
  "kernel": "5.15.0-76-generic",
  "processes": [
    {
      "pid": 1234,
      "name": "nginx",
      "exe": "/usr/sbin/nginx",
      "libraries": ["libssl.so.3"],
      "open_crypto_files": ["/etc/ssl/certs/server.crt", "/etc/ssl/private/server.key"],
      "running_as": "root"
    },
    {
      "pid": 5678,
      "name": "sshd",
      "exe": "/usr/sbin/sshd",
      "libraries": ["libssl.so.3", "libcrypto.so.3"],
      "open_crypto_files": ["/etc/ssh/ssh_host_rsa_key"],
      "running_as": "root"
    }
  ],
  "summary": {
    "total_processes": 2,
    "unique_libraries": 2,
    "total_files": 3
  }
}
```

**Postconditions:**
- Administrator has complete list of crypto usage
- Output can be saved for audit trail
- No system changes made

**Alternative Flow 1 (Save to file):**
- Step 1: `sudo crypto-tracer snapshot --output /var/log/crypto-audit-$(date +%Y%m%d).json`
- Result: Output saved to dated file

**Alternative Flow 2 (Human-readable summary):**
- Step 1: `sudo crypto-tracer snapshot --format summary`
- Result: Text summary instead of JSON

---

### Feature 2: Troubleshooting Certificate Issues

**Priority:** P0

**Description:** Developers can debug why their application can't load a certificate.

#### 4.2.1 Use Case: Debug "Certificate Not Found" Error

**Actor:** Developer

**Preconditions:**
- Application fails to start with "certificate not found" error
- Developer has sudo access

**Main Flow:**
1. Developer starts monitoring: `sudo crypto-tracer monitor --name myapp --duration 30 &`
2. Developer starts application: `./myapp`
3. Application attempts to load certificate
4. crypto-tracer captures file open attempts
5. Developer sees in output which files the app tried to open
6. Developer identifies the issue (wrong path, permissions, etc.)

**Example Output:**
```json
{"event_type": "process_exec", "timestamp": "2025-11-17T15:35:00.000Z", "pid": 9876, "process": "myapp", "cmdline": "./myapp --config /etc/myapp/config.yaml"}
{"event_type": "lib_load", "timestamp": "2025-11-17T15:35:00.123Z", "pid": 9876, "process": "myapp", "library": "/usr/lib/libssl.so.3"}
{"event_type": "file_open", "timestamp": "2025-11-17T15:35:00.234Z", "pid": 9876, "process": "myapp", "file": "/etc/myapp/cert.pem", "flags": "O_RDONLY", "result": "ENOENT"}
{"event_type": "file_open", "timestamp": "2025-11-17T15:35:00.235Z", "pid": 9876, "process": "myapp", "file": "/etc/myapp/server.crt", "flags": "O_RDONLY", "result": "success"}
{"event_type": "file_open", "timestamp": "2025-11-17T15:35:00.236Z", "pid": 9876, "process": "myapp", "file": "/etc/myapp/server.key", "flags": "O_RDONLY", "result": "EACCES"}
```

**Analysis:**
1. App tried `/etc/myapp/cert.pem` - **file not found** (ENOENT)
2. App tried `/etc/myapp/server.crt` - **success**
3. App tried `/etc/myapp/server.key` - **permission denied** (EACCES)

**Solution:** Fix permissions on `server.key`

**Postconditions:**
- Developer identified the issue
- Application can now start successfully

**Value:** Saved hours of debugging time

---

### Feature 3: Compliance Audit Trail

**Priority:** P1

**Description:** Compliance officers can generate audit evidence of crypto library usage.

#### 4.3.1 Use Case: FIPS 140-2 Compliance Verification

**Actor:** Compliance Officer

**Preconditions:**
- System must use FIPS-validated crypto libraries
- Compliance officer has access to run commands

**Main Flow:**
1. Compliance officer takes snapshot: `sudo crypto-tracer snapshot --output fips-audit-$(date +%Y%m%d).json`
2. Tool generates snapshot showing all crypto libraries
3. Officer reviews output to verify FIPS libraries in use
4. Officer runs filter: `jq '.processes[].libraries[]' fips-audit-*.json | sort | uniq`
5. Officer verifies all libraries are FIPS 140-2 validated
6. Officer saves output as audit evidence

**Example Analysis:**
```bash
$ jq '.processes[].libraries[]' fips-audit-20251117.json | sort | uniq
"/usr/lib/x86_64-linux-gnu/libssl.so.3"
"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"

$ dpkg -l | grep libssl3
ii  libssl3  3.0.2-0ubuntu1.10  OpenSSL 3.0.2 (FIPS)

✓ All libraries are FIPS 140-2 validated
```

**Postconditions:**
- Audit evidence generated
- Compliance verified
- Documentation for auditors

---

### Feature 4: Security Research

**Priority:** P2

**Description:** Security researchers can analyze cryptographic behavior of applications.

#### 4.4.1 Use Case: Study Certificate Validation Behavior

**Actor:** Security Researcher

**Preconditions:**
- Researcher wants to study how an application validates certificates
- Application available for testing

**Main Flow:**
1. Researcher starts monitoring: `sudo crypto-tracer monitor --name targetapp --output research.json &`
2. Researcher starts target application with test certificates
3. crypto-tracer captures all file access and API calls
4. Researcher stops monitoring after test (Ctrl+C)
5. Researcher analyzes JSON output with custom scripts

**Example Analysis:**
```bash
# Extract certificate access patterns
$ cat research.json | jq -r 'select(.event_type=="file_open") | .file' | grep -E '\.(crt|pem)$' | sort
/etc/ssl/certs/ca-certificates.crt
/home/USER/test-certs/expired.crt
/home/USER/test-certs/revoked.crt
/home/USER/test-certs/self-signed.crt
/home/USER/test-certs/valid.crt

# Count OpenSSL API calls
$ cat research.json | jq -r 'select(.event_type=="api_call") | .function_name' | sort | uniq -c
   1 SSL_CTX_new
   5 X509_verify_cert
   5 X509_check_host
```

**Findings:**
- Application loads 5 test certificates
- Performs X509 verification on each
- Checks hostname for each

**Postconditions:**
- Research data collected
- Application behavior understood
- Paper/report can be written

---

### Feature 5: DevOps Validation

**Priority:** P1

**Description:** DevOps engineers can validate deployment crypto configuration.

#### 4.5.1 Use Case: CI/CD Crypto Validation

**Actor:** DevOps Engineer

**Preconditions:**
- Application deployed to staging environment
- CI/CD pipeline running

**Main Flow:**
1. CI/CD pipeline includes validation step:
```bash
#!/bin/bash
# crypto-validation.sh

# Start application
./start-app.sh &
APP_PID=$!

# Monitor for 30 seconds
sudo crypto-tracer profile --pid $APP_PID --duration 30 --output crypto-profile.json

# Validate crypto usage
OPENSSL_VERSION=$(jq -r '.libraries[] | select(.name | contains("libssl")) | .path' crypto-profile.json | xargs dpkg -S | grep -oP 'libssl\d+')

if [ "$OPENSSL_VERSION" = "libssl3" ]; then
  echo "✓ Using OpenSSL 3.x"
else
  echo "✗ Not using OpenSSL 3.x"
  exit 1
fi

# Validate certificate access
CERT_PATH=$(jq -r '.files_accessed[] | select(.type=="certificate") | .path' crypto-profile.json)
if [ -z "$CERT_PATH" ]; then
  echo "✗ No certificate accessed"
  exit 1
else
  echo "✓ Certificate accessed: $CERT_PATH"
fi

echo "✓ All crypto validations passed"
```

**Postconditions:**
- Deployment validated
- Correct crypto libraries confirmed
- Certificate access verified
- CI/CD pipeline continues (green build)

---

## 5. External Interface Requirements

### 5.1 Command-Line Interface

See Section 3.1.1 for complete CLI specification.

**Summary of Commands:**
- `monitor` - Continuous monitoring with event stream
- `profile` - Detailed profile of specific process
- `snapshot` - Quick system-wide inventory
- `libs` - List crypto libraries
- `files` - Track crypto file access
- `--version` - Version information
- `--help` - Usage help

### 5.2 Output Interface

#### 5.2.1 JSON Event Format

See Section 3.1.3 (REQ-EVENT-003) for detailed event formats.

**Output Modes:**
1. **json-stream** (default) - Streaming JSON, one object per line
2. **json-lines** - Alias for json-stream
3. **json-array** - JSON array of events

#### 5.2.2 JSON Profile Format

See Section 3.1.1 (REQ-CLI-002) for profile structure.

**Key Sections:**
- `process` - Process metadata
- `libraries` - Loaded crypto libraries
- `files_accessed` - Crypto files accessed
- `api_calls` - API call counts
- `statistics` - Summary statistics

#### 5.2.3 JSON Snapshot Format

See Section 3.1.1 (REQ-CLI-003) for snapshot structure.

**Key Sections:**
- `processes` - Array of processes using crypto
- `summary` - Aggregate statistics

### 5.3 Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Insufficient privileges |
| 4 | Kernel not supported |
| 5 | eBPF load failed |
| 130 | Interrupted by user (SIGINT) |
| 143 | Terminated (SIGTERM) |

### 5.4 Logging Interface

**Standard Error (stderr):**
- Informational messages (unless --quiet)
- Warning messages
- Error messages
- Progress indicators

**Log Levels:**
- ERROR: Fatal errors
- WARN: Warnings (non-fatal)
- INFO: Informational messages
- DEBUG: Debug output (with --verbose)

**Example Log Output:**
```
[2025-11-17 15:30:00] INFO: crypto-tracer v1.0.0 starting
[2025-11-17 15:30:00] INFO: Kernel version: 5.15.0-76-generic
[2025-11-17 15:30:00] INFO: Loading eBPF programs...
[2025-11-17 15:30:01] INFO: eBPF programs loaded successfully
[2025-11-17 15:30:01] INFO: Monitoring started (duration: 60s)
[2025-11-17 15:30:45] WARN: High event rate: 8000/sec
[2025-11-17 15:31:01] INFO: Monitoring stopped
[2025-11-17 15:31:01] INFO: Total events captured: 45,234
[2025-11-17 15:31:01] INFO: Unloading eBPF programs...
[2025-11-17 15:31:01] INFO: Clean shutdown complete
```

---

## 6. Non-Functional Requirements

### 6.1 Performance Requirements

See Section 3.1.5 for detailed performance requirements.

**Summary:**
- CPU overhead: <0.5% average, <2% peak
- Memory footprint: <50MB RSS
- Startup time: <2 seconds
- Event latency: <50ms (99th percentile)
- Event throughput: 5,000 events/sec (no loss)

### 6.2 Security Requirements

See Section 3.1.4 for detailed security requirements.

**Summary:**
- Privilege validation at startup
- Read-only operation (no system modifications)
- Path redaction (privacy-preserving)
- No sensitive data in output
- BPF programs verified by kernel

### 6.3 Reliability Requirements

**Mean Time Between Failures (MTBF):** >7 days continuous operation

**Mean Time To Recover (MTTR):** Instant (restart tool)

**Availability:** Not applicable (on-demand tool, not daemon)

**Data Loss:**
- In-flight events may be lost on crash (acceptable)
- Completed events written to file are durable

**Graceful Degradation:**
- Continue with reduced functionality on non-critical failures
- Fail fast on critical failures

### 6.4 Portability Requirements

**Kernel Portability:**
- Support kernels 4.15 through 6.x
- Use BPF CO-RE for cross-kernel compatibility
- Detect and adapt to kernel features

**Distribution Portability:**
- Work on Ubuntu, Debian, RHEL, Fedora, Amazon Linux, Alpine
- No distribution-specific dependencies
- Standard Linux APIs only

**Architecture Portability:**
- x86_64 - Tier 1 support
- ARM64 - Tier 1 support
- Other architectures - Best effort

### 6.5 Maintainability Requirements

**Code Quality:**
- C11 standard compliance
- Comment-to-code ratio: >15%
- Cyclomatic complexity: <15 per function
- No compiler warnings (-Wall -Wextra -Werror)

**Documentation:**
- README with quick start guide
- Man page (crypto-tracer.1)
- Usage examples
- API documentation (Doxygen)

**Testing:**
- Unit test coverage: >70%
- Integration tests: All major features
- Compatibility tests: All listed distributions

**Build System:**
- Makefile (standard)
- Optional: CMake
- Dependencies clearly documented
- Reproducible builds

### 6.6 Usability Requirements

**Learning Curve:**
- Time to first value: <5 minutes for basic usage
- Advanced usage: <30 minutes with examples

**Documentation Completeness:**
- All commands documented
- All options documented
- Common use cases covered
- Troubleshooting guide

**Error Messages:**
- Clear and actionable
- Include solution suggestions
- Link to documentation

**Defaults:**
- Sensible defaults (no required config)
- Privacy-preserving by default
- Safe operation (read-only)

---

## 7. Appendices

### Appendix A: Data Dictionary

**Event Types:**

| Event Type | Description | Key Fields |
|------------|-------------|------------|
| `file_open` | File open operation | pid, file, flags, result |
| `lib_load` | Library loaded | pid, library, path |
| `process_exec` | Process started | pid, ppid, cmdline |
| `process_exit` | Process exited | pid, exit_code |
| `api_call` | Crypto API called (P1) | pid, function_name, library |

**File Types:**

| File Type | Extensions | Description |
|-----------|------------|-------------|
| `certificate` | .crt, .pem, .cer, .der | X.509 certificates |
| `private_key` | .key, .pem | Private keys |
| `keystore` | .p12, .pfx, .jks, .keystore | Keystores |
| `unknown` | - | Unrecognized crypto file |

**Library Types:**

| Library | Description | Common Paths |
|---------|-------------|--------------|
| OpenSSL | Most common SSL/TLS library | libssl.so.*, libcrypto.so.* |
| GnuTLS | Alternative SSL/TLS library | libgnutls.so.* |
| libsodium | Modern crypto library | libsodium.so.* |
| NSS | Mozilla crypto library | libnss3.so |
| mbedTLS | Embedded crypto library | libmbedtls.so.* |

---

### Appendix B: JSON Schema

**Event Schema (json-stream format):**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Crypto Tracer Event",
  "oneOf": [
    {
      "type": "object",
      "properties": {
        "event_type": {"const": "file_open"},
        "timestamp": {"type": "string", "format": "date-time"},
        "pid": {"type": "integer", "minimum": 1},
        "uid": {"type": "integer", "minimum": 0},
        "process": {"type": "string"},
        "file": {"type": "string"},
        "flags": {"type": "string"},
        "file_type": {"type": "string", "enum": ["certificate", "private_key", "keystore", "unknown"]},
        "result": {"type": "string"}
      },
      "required": ["event_type", "timestamp", "pid", "process", "file"]
    },
    {
      "type": "object",
      "properties": {
        "event_type": {"const": "lib_load"},
        "timestamp": {"type": "string", "format": "date-time"},
        "pid": {"type": "integer", "minimum": 1},
        "uid": {"type": "integer", "minimum": 0},
        "process": {"type": "string"},
        "library": {"type": "string"},
        "library_name": {"type": "string"}
      },
      "required": ["event_type", "timestamp", "pid", "process", "library"]
    },
    {
      "type": "object",
      "properties": {
        "event_type": {"const": "process_exec"},
        "timestamp": {"type": "string", "format": "date-time"},
        "pid": {"type": "integer", "minimum": 1},
        "ppid": {"type": "integer", "minimum": 0},
        "uid": {"type": "integer", "minimum": 0},
        "process": {"type": "string"},
        "cmdline": {"type": "string"}
      },
      "required": ["event_type", "timestamp", "pid", "ppid", "process"]
    }
  ]
}
```

**Profile Schema:**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Crypto Tracer Profile",
  "type": "object",
  "properties": {
    "profile_version": {"type": "string"},
    "generated_at": {"type": "string", "format": "date-time"},
    "duration_seconds": {"type": "integer", "minimum": 0},
    "process": {
      "type": "object",
      "properties": {
        "pid": {"type": "integer"},
        "name": {"type": "string"},
        "exe": {"type": "string"},
        "cmdline": {"type": "string"},
        "uid": {"type": "integer"},
        "gid": {"type": "integer"},
        "start_time": {"type": "string", "format": "date-time"}
      }
    },
    "libraries": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "path": {"type": "string"},
          "load_time": {"type": "string", "format": "date-time"}
        }
      }
    },
    "files_accessed": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "path": {"type": "string"},
          "type": {"type": "string"},
          "access_count": {"type": "integer"},
          "first_access": {"type": "string", "format": "date-time"},
          "last_access": {"type": "string", "format": "date-time"},
          "mode": {"type": "string"}
        }
      }
    },
    "api_calls": {
      "type": "object",
      "additionalProperties": {"type": "integer"}
    },
    "statistics": {
      "type": "object",
      "properties": {
        "total_events": {"type": "integer"},
        "libraries_loaded": {"type": "integer"},
        "files_accessed": {"type": "integer"},
        "api_calls_made": {"type": "integer"}
      }
    }
  },
  "required": ["profile_version", "generated_at", "process", "libraries", "files_accessed", "statistics"]
}
```

---

### Appendix C: Usage Examples

**Example 1: Quick Inventory**
```bash
# Take snapshot of all crypto usage
sudo crypto-tracer snapshot

# Save to file
sudo crypto-tracer snapshot --output crypto-inventory.json

# Human-readable summary
sudo crypto-tracer snapshot --format summary
```

**Example 2: Monitor Specific Service**
```bash
# Monitor nginx for 5 minutes
sudo crypto-tracer monitor --name nginx --duration 300 --output nginx-crypto.json

# Monitor specific PID
sudo crypto-tracer monitor --pid 1234 --duration 60
```

**Example 3: Profile Application**
```bash
# Profile application for 30 seconds
sudo crypto-tracer profile --name myapp --duration 30 --output myapp-profile.json

# Pretty-print profile
sudo crypto-tracer profile --name myapp --format json-pretty
```

**Example 4: CI/CD Integration**
```bash
#!/bin/bash
# validate-crypto.sh

# Start application
./start-app.sh &
APP_PID=$!
sleep 5  # Let app initialize

# Profile crypto usage
sudo crypto-tracer profile --pid $APP_PID --duration 10 --output /tmp/crypto.json

# Check for OpenSSL 3.x
if jq -e '.libraries[] | select(.name | contains("libssl3"))' /tmp/crypto.json > /dev/null; then
  echo "✓ Using OpenSSL 3.x"
  exit 0
else
  echo "✗ Not using OpenSSL 3.x"
  exit 1
fi
```

**Example 5: Security Audit**
```bash
# Monitor for 1 hour, save all events
sudo crypto-tracer monitor --duration 3600 --output audit-$(date +%Y%m%d-%H%M).json

# Later analysis: Which certificates were accessed?
cat audit-*.json | jq -r 'select(.event_type=="file_open" and .file_type=="certificate") | .file' | sort | uniq
```

**Example 6: Troubleshooting**
```bash
# Application won't start, why?
sudo crypto-tracer monitor --name failing-app --duration 10 --verbose

# Look for ENOENT (file not found) or EACCES (permission denied)
# in the output
```

---

### Appendix D: Build Instructions

**Prerequisites:**
```bash
# Ubuntu/Debian
sudo apt-get install build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev linux-headers-$(uname -r)

# RHEL/Fedora
sudo dnf install gcc clang llvm libbpf-devel elfutils-libelf-devel zlib-devel kernel-devel

# Alpine
sudo apk add build-base clang llvm libbpf-dev elfutils-dev zlib-dev linux-headers
```

**Build:**
```bash
# Clone repository
git clone https://github.com/yourusername/crypto-tracer.git
cd crypto-tracer

# Build
make

# Install
sudo make install

# Run tests
make test
```

**Build Options:**
```bash
# Static build (for portability)
make static

# Debug build
make debug

# Build with CMake
mkdir build && cd build
cmake ..
make
```

---

### Appendix E: Installation

**Binary Release:**
```bash
# Download latest release
wget https://github.com/yourusername/crypto-tracer/releases/download/v1.0.0/crypto-tracer-linux-x86_64

# Make executable
chmod +x crypto-tracer-linux-x86_64

# Move to PATH
sudo mv crypto-tracer-linux-x86_64 /usr/local/bin/crypto-tracer

# Verify
crypto-tracer --version
```

**Package Installation:**
```bash
# Ubuntu/Debian (when available)
sudo apt-get install crypto-tracer

# RHEL/Fedora (when available)
sudo dnf install crypto-tracer

# Arch (AUR, when available)
yay -S crypto-tracer
```

**Grant Capabilities:**
```bash
# Grant CAP_BPF (recommended)
sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/crypto-tracer

# Or CAP_SYS_ADMIN (older kernels)
sudo setcap cap_sys_admin+ep /usr/local/bin/crypto-tracer

# Now can run without sudo
crypto-tracer snapshot
```

---

### Appendix F: Troubleshooting

**Problem: "Error: Insufficient privileges"**
```
Solution 1: Run with sudo
  sudo crypto-tracer monitor

Solution 2: Grant capability
  sudo setcap cap_bpf+ep /usr/local/bin/crypto-tracer

Solution 3: Check capability
  getcap /usr/local/bin/crypto-tracer
```

**Problem: "Error: Kernel version not supported"**
```
Solution: Upgrade kernel to 4.15+
  - Ubuntu 18.04+ (kernel 4.15+)
  - Debian 10+ (kernel 4.19+)
  - RHEL 8+ (kernel 4.18+)

Check current kernel:
  uname -r
```

**Problem: "No events captured"**
```
Debug:
  1. Verify eBPF programs loaded:
     sudo bpftool prog list

  2. Check for active processes using crypto:
     sudo crypto-tracer snapshot

  3. Run with verbose logging:
     sudo crypto-tracer monitor --verbose

  4. Check kernel logs:
     sudo dmesg | tail
```

**Problem: "High CPU usage"**
```
Possible causes:
  1. Very high event rate (>10,000/sec)
     - Check: cat output.json | wc -l
     - Solution: Use filters (--pid, --name)

  2. Many processes being monitored
     - Solution: Monitor specific process

  3. Slow disk (if writing to file)
     - Solution: Use faster disk or write to /dev/shm
```

---

### Appendix G: FAQ

**Q: Does this tool decrypt TLS traffic?**  
A: No. crypto-tracer only observes which crypto libraries and files are accessed. It does not decrypt any traffic.

**Q: Can I use this in production?**  
A: Yes. The tool has minimal overhead (<0.5% CPU) and is read-only. However, test in staging first.

**Q: Does this work in containers (Docker)?**  
A: Yes, but you need to run it on the host with elevated privileges. It can monitor processes inside containers.

**Q: Does this work on Kubernetes?**  
A: Yes. Run as a DaemonSet with hostPID and privileged security context.

**Q: How is this different from bpftrace?**  
A: bpftrace is a general tracing tool. crypto-tracer is specialized for cryptographic monitoring with ready-to-use commands and structured JSON output.

**Q: Can I integrate this with my SIEM?**  
A: Yes. The JSON output can be sent to any SIEM that accepts JSON logs (Splunk, ELK, etc.).

**Q: Is there a GUI?**  
A: Not in v1.0. This is a CLI-only tool designed for automation and integration.

**Q: What about Windows or macOS?**  
A: Not supported. This tool relies on Linux eBPF technology.

**Q: How do I contribute?**  
A: See CONTRIBUTING.md in the repository. Pull requests welcome!

---

### Appendix H: License

**Proposed License:** MIT License

```
MIT License

Copyright (c) 2025 [Your Name/Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Document Approval

**Approval Signatures:**

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Project Lead | [Name] | _____________ | _____ |
| Technical Architect | [Name] | _____________ | _____ |
| Lead Developer | [Name] | _____________ | _____ |

---

**END OF DOCUMENT**

**Document Version:** 1.0  
**Date:** November 17, 2025  
**Project:** crypto-tracer - Standalone eBPF Crypto Monitoring Tool  
**Classification:** Open Source Project Specification  
**License:** MIT (proposed)
