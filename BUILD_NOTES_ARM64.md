# Building crypto-tracer on ARM64 (EC2 Graviton)

This document provides guidance for building crypto-tracer on ARM64 architecture, specifically tested on AWS EC2 Graviton instances.

## Overview

While crypto-tracer is primarily developed and tested on x86_64, it can be built on ARM64 systems with some modifications. This has been successfully tested on AWS EC2 t4g instances (Graviton2).

## Prerequisites

### Install Required Packages

On Ubuntu/Debian ARM64:

```bash
# Core build tools
sudo apt update
sudo apt install -y gcc clang make

# eBPF development
sudo apt install -y libbpf-dev libelf-dev zlib1g-dev

# Kernel headers for your running kernel
sudo apt install -y linux-headers-$(uname -r)

# BPF tools
sudo apt install -y linux-tools-common linux-tools-generic
# Or on some systems:
sudo apt install -y linux-tools-$(uname -r)

# Additional dependencies
sudo apt install -y libcap-dev
```

## Required Makefile Modifications

The default Makefile is configured for x86_64. For ARM64 builds, you need to make the following changes:

### 1. Architecture Detection

Add architecture detection after the tool configuration section:

```makefile
# Detect architecture for library paths
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    LIB_ARCH := aarch64-linux-gnu
    BPF_ARCH := arm64
else ifeq ($(ARCH),x86_64)
    LIB_ARCH := x86_64-linux-gnu
    BPF_ARCH := x86
else
    LIB_ARCH := $(ARCH)-linux-gnu
    BPF_ARCH := $(ARCH)
endif
```

### 2. Update LDFLAGS

Change the LDFLAGS line to use architecture-specific library paths:

```makefile
# Before:
LDFLAGS := -lelf -lz -lbpf -lcap

# After:
LDFLAGS := -L/usr/lib/$(LIB_ARCH) -lz -lcap -lelf -lbpf
```

### 3. Update BPF_CFLAGS

Change the BPF target architecture:

```makefile
# Before:
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -Wall -O2 -g

# After:
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -O2 -g
```

### 4. Add Header Search Paths

Add these lines after CFLAGS definition to help find libbpf headers:

```makefile
# Try to find libbpf headers in common locations
ifneq ($(wildcard /usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include),)
    CFLAGS += -I/usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include
endif
```

And for BPF_CFLAGS:

```makefile
BPF_CFLAGS += -I/usr/include
ifneq ($(wildcard /usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include),)
    BPF_CFLAGS += -I/usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include
endif
```

### 5. Update Static Build Section

```makefile
# Before:
ifdef STATIC
    LDFLAGS := -lbpf -lelf -lz -lcap -static
    CFLAGS += -DSTATIC_BUILD
endif

# After:
ifdef STATIC
    LDFLAGS := -L/usr/lib/$(LIB_ARCH)
    LDFLAGS += -lbpf -lelf -lz -lcap
    LDFLAGS += -static
    CFLAGS += -DSTATIC_BUILD
endif
```

## Building

After making the Makefile modifications:

```bash
# Check dependencies
make check-deps

# Build
make clean
make

# Build static binary (for distribution)
make static
```

## Known Issues on ARM64

### 1. Symbol Conflicts with Static Linking

When building with static linking, you may encounter symbol conflicts between crypto-tracer's internal functions and libbpf:

```
multiple definition of `glob_match'
```

**Solution:** The function `glob_match` in `src/event_processor.c` has been renamed to `crypto_glob_match` to avoid conflicts.

### 2. Library Path Issues

ARM64 systems use different library paths (`/usr/lib/aarch64-linux-gnu/`) compared to x86_64 (`/usr/lib/x86_64-linux-gnu/`). The Makefile modifications above handle this automatically.

### 3. Kernel Header Locations

On some ARM64 systems, kernel headers may be in non-standard locations. The Makefile modifications include search paths for common locations.

## Testing on ARM64

After building, test the binary:

```bash
# Check capabilities
./build/crypto-tracer --version

# Test with a simple monitor (requires root or capabilities)
sudo ./build/crypto-tracer monitor --duration 5

# Test file access
sudo ./build/crypto-tracer files --duration 5
```

## EC2 Graviton-Specific Notes

### Instance Types Tested

- **t4g.micro**: Successfully built and tested
- **t4g.small**: Successfully built and tested

### Disk Space Requirements

- Minimum: 2GB free space for build artifacts
- Recommended: 5GB free space for comfortable development

### Performance

ARM64 builds perform comparably to x86_64 builds. eBPF overhead remains <0.5% CPU on Graviton2 processors.

## Cross-Compilation

For cross-compiling from x86_64 to ARM64, you'll need:

```bash
# On x86_64 host
sudo apt install -y gcc-aarch64-linux-gnu
sudo apt install -y libbpf-dev:arm64 libelf-dev:arm64

# Then build with cross-compiler
make CC=aarch64-linux-gnu-gcc
```

Note: Cross-compilation of eBPF programs is complex and not fully tested.

## Distribution

When distributing ARM64 binaries:

1. Build with static linking: `make static`
2. Test on target ARM64 system
3. Include architecture in package name: `crypto-tracer-1.0.0-arm64.tar.gz`
4. Document ARM64-specific requirements in release notes

## Reverting to x86_64

To revert the Makefile back to x86_64-only:

```bash
git checkout Makefile
```

Or manually remove the architecture detection sections and restore the original hardcoded values.

## Support Status

- **x86_64**: Tier 1 support (primary development platform)
- **ARM64**: Tier 2 support (tested, requires manual Makefile modifications)
- **Other architectures**: Untested

## Getting Help

If you encounter issues building on ARM64:

1. Check that all prerequisites are installed
2. Verify kernel version is 4.15+ with eBPF support
3. Check `/sys/kernel/btf/vmlinux` exists for CO-RE support
4. Review build logs for specific error messages
5. Open an issue on GitHub with:
   - Architecture: `uname -m`
   - Kernel version: `uname -r`
   - Distribution: `cat /etc/os-release`
   - Full build output

## Future Plans

Future versions may include:

- Automatic architecture detection in Makefile
- Pre-built ARM64 binaries in releases
- CI/CD testing on ARM64
- Improved cross-compilation support
