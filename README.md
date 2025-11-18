# crypto-tracer

A standalone eBPF-based command-line tool for monitoring cryptographic operations on Linux systems.

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

## License

GPL v3.0 