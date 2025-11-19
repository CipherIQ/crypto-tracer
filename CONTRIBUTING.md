# Contributing to crypto-tracer

Thank you for your interest in contributing to crypto-tracer! This document provides guidelines and instructions for contributing.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Making Changes](#making-changes)
5. [Testing](#testing)
6. [Submitting Changes](#submitting-changes)
7. [Coding Standards](#coding-standards)
8. [eBPF Development Guidelines](#ebpf-development-guidelines)
9. [Creating Releases](#creating-releases)

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Linux system with kernel 4.15+ (5.8+ recommended)
- gcc 10+ or clang 11+
- libbpf-dev, libelf-dev, zlib1g-dev
- bpftool (for skeleton generation)
- Git

### Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/crypto-tracer.git
cd crypto-tracer

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/crypto-tracer.git
```

## Development Setup

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install gcc clang libbpf-dev libelf-dev zlib1g-dev
sudo apt install linux-tools-common linux-tools-generic
sudo apt install valgrind  # For memory leak detection
```

**RHEL/Fedora:**
```bash
sudo dnf install gcc clang libbpf-devel elfutils-libelf-devel zlib-devel
sudo dnf install bpftool valgrind
```

### Build the Project

```bash
# Check dependencies
make check-deps

# Build with debug symbols
make debug

# Run tests
make test
```

### Verify Your Setup

```bash
# Test basic functionality
./build/crypto-tracer snapshot

# Test with sudo
sudo ./build/crypto-tracer monitor --duration 5
```

## Making Changes

### Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create a feature branch
git checkout -b feature/your-feature-name
```

### Branch Naming Conventions

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions or modifications

### Commit Messages

Follow conventional commit format:

```
type(scope): brief description

Detailed explanation of the change (if needed).

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Build system or auxiliary tool changes

**Examples:**
```
feat(monitor): add support for filtering by UID

Add --uid option to filter events by user ID. This is useful
for monitoring crypto activity of specific users.

Fixes #42
```

```
fix(ebpf): resolve verifier rejection in file_open_trace

Simplified string processing logic to avoid variable-offset
memory access that was causing BPF verifier rejection on
kernel 5.4.

Fixes #56
```

## Testing

### Run All Tests

```bash
make test
```

### Run Specific Test Suites

```bash
# Unit tests only
make test-unit

# Integration tests only
make test-integration
```

### Add New Tests

**Unit Tests:**
- Add to `tests/unit/`
- Test individual functions and modules
- Use mock data where appropriate
- Keep tests fast (<1 second each)

**Integration Tests:**
- Add to `tests/integration/`
- Test complete workflows
- May require elevated privileges
- Document any special requirements

### Memory Leak Testing

```bash
# Check for memory leaks
make memcheck

# Or manually with valgrind
valgrind --leak-check=full --show-leak-kinds=all \
    ./build/crypto-tracer snapshot
```

### Test Your Changes

Before submitting:

1. **Build succeeds:** `make clean && make`
2. **Tests pass:** `make test`
3. **No memory leaks:** `make memcheck`
4. **Manual testing:** Test your changes manually
5. **Documentation updated:** Update relevant docs

## Submitting Changes

### Before Submitting

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] No memory leaks
- [ ] Documentation updated
- [ ] Commit messages follow conventions
- [ ] Branch is up to date with upstream main

### Create Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Go to GitHub and create a Pull Request

3. Fill out the PR template:
   - Description of changes
   - Related issues
   - Testing performed
   - Screenshots (if UI changes)

4. Wait for review and address feedback

### PR Review Process

- Maintainers will review your PR
- Address any requested changes
- Once approved, your PR will be merged

## Coding Standards

### General Guidelines

- **C11 standard compliance**
- **No GNU extensions** in portable code
- **Compile with `-Wall -Wextra -Werror`**
- **No memory leaks** (verified with valgrind)
- **Bounds checking** on all array access
- **Safe string handling** (no strcpy, use strncpy/strlcpy)

### Code Style

**Indentation:**
- Use 4 spaces (no tabs)
- Indent case labels in switch statements

**Naming:**
- Functions: `snake_case()`
- Variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Types: `snake_case_t`
- Structs: `struct snake_case`

**Example:**
```c
#define MAX_PATH_LEN 256

typedef struct {
    int field_one;
    char *field_two;
} my_struct_t;

static int helper_function(const char *input) {
    if (!input) {
        return -1;
    }
    // Implementation
    return 0;
}

int public_function(my_struct_t *data) {
    if (!data) {
        return -EINVAL;
    }
    
    int result = helper_function(data->field_two);
    if (result < 0) {
        return result;
    }
    
    return 0;
}
```

### File Headers

All source files must include:

```c
// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

/**
 * filename.c - Brief description
 * 
 * Detailed description of the file's purpose and functionality.
 */
```

### Error Handling

- Check all return values
- Use negative errno values for errors
- Provide clear error messages
- Clean up resources in error paths

**Example:**
```c
int process_data(const char *input) {
    char *buffer = NULL;
    int fd = -1;
    int ret = 0;
    
    // Validate input
    if (!input) {
        return -EINVAL;
    }
    
    // Allocate resources
    buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        ret = -ENOMEM;
        goto cleanup;
    }
    
    // Open file
    fd = open(input, O_RDONLY);
    if (fd < 0) {
        ret = -errno;
        goto cleanup;
    }
    
    // Process...
    
cleanup:
    if (buffer) {
        free(buffer);
    }
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}
```

## eBPF Development Guidelines

### eBPF Program Rules

1. **Keep it simple** - Complex logic belongs in user-space
2. **No variable-offset memory access** - Verifier will reject
3. **No unbounded loops** - Use fixed iterations or `#pragma unroll`
4. **Fixed-size operations only** - No dynamic memory allocation
5. **Validate all pointers** - Check before dereferencing

### eBPF Best Practices

**DO:**
- Use `BPF_CORE_READ()` for portable struct access
- Implement proper bounds checking
- Use helper functions for kernel memory access
- Keep programs under 4096 instructions
- Test on multiple kernel versions

**DON'T:**
- Use variable-length loops
- Access memory with variable offsets
- Use string functions (strlen, strcmp, etc.)
- Allocate memory dynamically
- Assume specific kernel versions

### Example eBPF Program

```c
// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * Copyright (c) 2025 Graziano Labs Corp.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct file_open_event *event;
    
    // Reserve ring buffer space
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event with fixed-size operations only
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Testing eBPF Programs

```bash
# Compile eBPF program
make build/your_program.bpf.o

# Test loading with bpftool
sudo bpftool prog load build/your_program.bpf.o /sys/fs/bpf/test

# Check for verifier errors
sudo dmesg | tail -50

# Clean up
sudo rm /sys/fs/bpf/test
```

## Documentation

### Update Documentation

When making changes, update relevant documentation:

- **README.md** - For user-facing changes
- **TROUBLESHOOTING.md** - For new issues or solutions
- **Man page** (crypto-tracer.1) - For command changes
- **Code comments** - For implementation details
- **.kiro/docs/** - For task verification

### Documentation Style

- Use clear, concise language
- Provide examples
- Include command output where helpful
- Keep formatting consistent

## Getting Help

### Resources

- **Documentation:** See README.md and TROUBLESHOOTING.md
- **Examples:** See DEMO.md
- **eBPF Resources:** https://ebpf.io/
- **libbpf Documentation:** https://libbpf.readthedocs.io/

### Ask Questions

- **GitHub Discussions:** For general questions
- **GitHub Issues:** For bug reports and feature requests
- **Pull Request Comments:** For code-specific questions

## License

By contributing to crypto-tracer, you agree that your contributions will be licensed under the GPL-3.0-or-later license.

---

Thank you for contributing to crypto-tracer! 🎉


## Creating Releases

### Building Distribution Packages

For creating official releases, always use static linking for maximum portability:

```bash
# Create static binary distribution package
make package-static
```

This creates `build/package/crypto-tracer-1.0.0.tar.gz` containing:
- Statically linked binary (~1.7MB, stripped)
- Man page
- Complete documentation
- License file

### Why Static Linking for Releases?

**Advantages:**
- ✅ Works across different Linux distributions
- ✅ No dependency on system library versions
- ✅ Users don't need to install libbpf, libelf, etc.
- ✅ Single self-contained binary
- ✅ Easier deployment

**Note:** The binary is larger (~1.7MB vs ~200KB dynamic), but this is acceptable for the portability benefits.

### Release Checklist

Before creating a release:

1. **Update version number** in `Makefile`:
   ```makefile
   VERSION := 1.0.0
   ```

2. **Run full test suite**:
   ```bash
   make clean
   make test
   ```

3. **Build static package**:
   ```bash
   make package-static
   ```

4. **Test the package**:
   ```bash
   cd /tmp
   tar xzf /path/to/crypto-tracer-1.0.0.tar.gz
   cd crypto-tracer-1.0.0
   sudo setcap cap_bpf,cap_perfmon+ep ./crypto-tracer
   ./crypto-tracer snapshot
   ```

5. **Verify binary is static**:
   ```bash
   ldd ./crypto-tracer
   # Should output: "not a dynamic executable"
   ```

6. **Create GitHub release**:
   - Tag: `v1.0.0`
   - Title: `crypto-tracer v1.0.0`
   - Attach: `crypto-tracer-1.0.0.tar.gz`
   - Include release notes

### Release Notes Template

```markdown
## crypto-tracer v1.0.0

### Features
- List new features

### Bug Fixes
- List bug fixes

### Installation

Download and extract:
\`\`\`bash
tar xzf crypto-tracer-1.0.0.tar.gz
cd crypto-tracer-1.0.0
\`\`\`

Grant capabilities:
\`\`\`bash
sudo setcap cap_bpf,cap_perfmon+ep ./crypto-tracer
\`\`\`

Run:
\`\`\`bash
./crypto-tracer snapshot
\`\`\`

See README.md for complete documentation.

### Requirements
- Linux kernel 4.15+ (5.8+ recommended)
- CAP_BPF or CAP_SYS_ADMIN capability (or run with sudo)

### Package Contents
- Statically linked binary (1.7MB)
- Man page
- Complete documentation
- License
```

### Distribution Channels

**GitHub Releases:**
- Primary distribution method
- Attach tarball to release
- Include checksums (SHA256)

**Package Repositories (Future):**
- Debian/Ubuntu: `.deb` package
- RHEL/Fedora: `.rpm` package
- Arch: AUR package

---

Thank you for contributing to crypto-tracer! 🎉
