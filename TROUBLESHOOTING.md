# crypto-tracer Troubleshooting Guide

This guide covers common issues and their solutions when using crypto-tracer.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Permission and Privilege Issues](#permission-and-privilege-issues)
3. [eBPF Program Loading Issues](#ebpf-program-loading-issues)
4. [Event Capture Issues](#event-capture-issues)
5. [Performance Issues](#performance-issues)
6. [Output and Formatting Issues](#output-and-formatting-issues)
7. [Kernel Compatibility Issues](#kernel-compatibility-issues)
8. [Build Issues](#build-issues)

---

## Installation Issues

### Issue: Dependencies Not Found

**Symptoms:**
```
Package 'libbpf-dev' has no installation candidate
```

**Solutions:**

**Ubuntu/Debian:**
```bash
# Update package lists
sudo apt update

# For Ubuntu 20.04 or later
sudo apt install gcc clang libbpf-dev libelf-dev zlib1g-dev

# For older Ubuntu versions, you may need to add a PPA
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install libbpf-dev
```

**RHEL/Fedora:**
```bash
# Enable EPEL repository (RHEL)
sudo dnf install epel-release

# Install dependencies
sudo dnf install gcc clang libbpf-devel elfutils-libelf-devel zlib-devel
```

**Alpine Linux:**
```bash
apk add gcc clang libbpf-dev elfutils-dev zlib-dev linux-headers
```

### Issue: bpftool Not Found

**Symptoms:**
```
make: bpftool: Command not found
```

**Solutions:**

**Ubuntu/Debian:**
```bash
sudo apt install linux-tools-common linux-tools-generic

# If that doesn't work, install for your specific kernel
sudo apt install linux-tools-$(uname -r)
```

**RHEL/Fedora:**
```bash
sudo dnf install bpftool
```

**Alpine Linux:**
```bash
apk add bpftool
```

**Build from source (if package not available):**
```bash
git clone https://github.com/libbpf/bpftool.git
cd bpftool/src
make
sudo make install
```

---

## Permission and Privilege Issues

### Issue: Permission Denied

**Symptoms:**
```
Error: Permission denied
Failed to load eBPF programs: Operation not permitted
```

**Cause:** Insufficient privileges to load eBPF programs.

**Understanding Linux Capabilities:**

Linux capabilities allow you to grant specific privileges to programs without making them fully root. For eBPF programs, you need:
- `CAP_BPF` - Permission to load eBPF programs (kernel 5.8+)
- `CAP_PERFMON` - Permission to read performance events
- `CAP_SYS_ADMIN` - Older alternative for kernels < 5.8

**Solutions:**

**Option 1: Run with sudo (simplest, works everywhere)**
```bash
sudo ./build/crypto-tracer monitor
```
- ✅ Works on all systems
- ✅ No setup required
- ❌ Need to enter password each time
- ❌ Runs with full root privileges

**Option 2: Grant CAP_BPF capability (recommended for kernel 5.8+)**
```bash
# One-time setup - grant capabilities to the binary
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer

# Now you can run without sudo
./build/crypto-tracer monitor
```
- ✅ Most secure option (minimal privileges)
- ✅ No password needed after setup
- ✅ Works for all users
- ❌ Only works on kernel 5.8+
- ⚠️ Must re-grant after rebuilding

**Option 3: Grant CAP_SYS_ADMIN capability (for older kernels < 5.8)**
```bash
# For kernels that don't support CAP_BPF
sudo setcap cap_sys_admin+ep ./build/crypto-tracer

# Now you can run without sudo
./build/crypto-tracer monitor
```
- ✅ Works on older kernels
- ✅ No password needed after setup
- ❌ Grants more privileges than necessary
- ⚠️ Must re-grant after rebuilding

**Check current capabilities:**
```bash
# Check if binary has capabilities
getcap ./build/crypto-tracer

# Expected output (kernel 5.8+):
# ./build/crypto-tracer = cap_bpf,cap_perfmon+ep

# Expected output (older kernels):
# ./build/crypto-tracer = cap_sys_admin+ep

# Check your user's capabilities
capsh --print
```

**Remove capabilities:**
```bash
# If you want to remove capabilities
sudo setcap -r ./build/crypto-tracer
```

### Issue: CAP_BPF Not Available

**Symptoms:**
```
Error: CAP_BPF capability not available on this kernel
```

**Cause:** Kernel version < 5.8 doesn't support CAP_BPF.

**Solutions:**

**Use CAP_SYS_ADMIN instead (older kernels):**
```bash
sudo setcap cap_sys_admin+ep ./build/crypto-tracer
```

**Or run as root:**
```bash
sudo ./build/crypto-tracer monitor
```

### Issue: Capabilities Lost After Rebuild

**Cause:** Capabilities are tied to the binary inode. Rebuilding creates a new binary.

**Solution:** Re-grant capabilities after each build:
```bash
make
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer
```

**Tip:** Create a script to automate this:
```bash
#!/bin/bash
make && sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer
```

---

## eBPF Program Loading Issues

### Issue: BPF Verifier Rejection

**Symptoms:**
```
libbpf: prog 'trace_file_open': BPF program load failed: Permission denied
libbpf: -- BEGIN PROG LOAD LOG --
invalid indirect read from stack
-- END PROG LOAD LOG --
```

**Cause:** eBPF program doesn't pass kernel verifier safety checks.

**Solutions:**

**Enable verbose logging to see full verifier output:**
```bash
sudo ./build/crypto-tracer monitor --verbose
```

**Check kernel version:**
```bash
uname -r
# Minimum required: 4.15
# Recommended: 5.8+
```

**Rebuild with debug symbols:**
```bash
make clean
make debug
sudo ./build/crypto-tracer monitor --verbose
```

**If issue persists:** This is likely a bug. Please report with:
- Kernel version (`uname -r`)
- Distribution (`cat /etc/os-release`)
- Full verifier log output

### Issue: vmlinux.h Generation Failed

**Symptoms:**
```
Warning: BTF not available, using fallback vmlinux.h
```

**Cause:** Kernel doesn't have BTF (BPF Type Format) support.

**Impact:** This is usually not a problem. The build system automatically uses a fallback header.

**To enable BTF (if you want):**
1. Ensure kernel is compiled with `CONFIG_DEBUG_INFO_BTF=y`
2. Check if BTF is available: `ls -la /sys/kernel/btf/vmlinux`
3. If not, you may need to upgrade your kernel or distribution

### Issue: Ring Buffer Creation Failed

**Symptoms:**
```
Error: Failed to create ring buffer
libbpf: failed to create ring buffer: Cannot allocate memory
```

**Cause:** Insufficient memory or kernel limits.

**Solutions:**

**Check available memory:**
```bash
free -h
```

**Check BPF memory limits:**
```bash
# Check current limit
ulimit -l

# Increase limit (temporary)
ulimit -l unlimited

# Or set in /etc/security/limits.conf (permanent)
echo "* soft memlock unlimited" | sudo tee -a /etc/security/limits.conf
echo "* hard memlock unlimited" | sudo tee -a /etc/security/limits.conf
```

---

## Event Capture Issues

### Issue: No Events Captured

**Symptoms:**
```
# Monitor runs but no events are shown
sudo ./build/crypto-tracer monitor --duration 10
# ... no output ...
```

**Diagnosis Steps:**

**1. Verify eBPF programs loaded:**
```bash
sudo ./build/crypto-tracer monitor --verbose
# Look for "Successfully loaded" messages
```

**2. Check if target process is using crypto:**
```bash
# Find the process
ps aux | grep myapp

# Check loaded libraries
sudo lsof -p <PID> | grep -E "libssl|libcrypto"

# Check open files
sudo lsof -p <PID> | grep -E "\.pem|\.crt|\.key"
```

**3. Generate test activity:**
```bash
# In one terminal
sudo ./build/crypto-tracer monitor --verbose

# In another terminal
cat /etc/ssl/certs/ca-certificates.crt > /dev/null
openssl version
```

**4. Check filters:**
```bash
# Remove all filters to see all events
sudo ./build/crypto-tracer monitor --duration 10
```

### Issue: Missing Events from Child Processes

**Symptoms:**
```
# Profiling by PID but missing file access events
sudo ./build/crypto-tracer profile --pid 1234
# Profile shows no files accessed, but you know the process accessed files
```

**Cause:** Child processes have different PIDs. If a bash script spawns `cat` to read a file, the file access happens in the child process.

**Solutions:**

**Use process name instead of PID:**
```bash
# Instead of:
sudo ./build/crypto-tracer profile --pid 1234

# Use:
sudo ./build/crypto-tracer profile --name myapp
```

**Use monitor command to see all events:**
```bash
sudo ./build/crypto-tracer monitor --name myapp
```

**Future enhancement:** `--follow-children` flag (not yet implemented)

### Issue: Events from Wrong Process

**Symptoms:**
```
# Filtering by process name but seeing events from other processes
sudo ./build/crypto-tracer monitor --name nginx
# Shows events from nginx-worker, nginx-master, etc.
```

**Cause:** Process name filter uses substring matching.

**Solution:** Use more specific filter or post-process with jq:
```bash
# Filter in post-processing
sudo ./build/crypto-tracer monitor --format json-stream | \
    jq 'select(.process == "nginx")'
```

---

## Performance Issues

### Issue: High CPU Usage

**Symptoms:**
```
# crypto-tracer using >5% CPU
top
# Shows crypto-tracer at high CPU
```

**Causes and Solutions:**

**1. High event volume:**
```bash
# Check event rate
sudo ./build/crypto-tracer monitor --duration 10 --verbose
# Look for "events processed" in output
```

**2. Use filters to reduce event volume:**
```bash
# Filter by specific process
sudo ./build/crypto-tracer monitor --name nginx

# Filter by specific files
sudo ./build/crypto-tracer monitor --file "*.pem"
```

**3. Use json-stream format (most efficient):**
```bash
sudo ./build/crypto-tracer monitor --format json-stream
```

### Issue: High Memory Usage

**Symptoms:**
```
# crypto-tracer using >100MB memory
```

**Causes:**
- Very long monitoring duration with many unique events
- Profile command with many files/libraries

**Solutions:**

**1. Use shorter monitoring durations:**
```bash
sudo ./build/crypto-tracer profile --duration 30  # Instead of 300
```

**2. Use monitor instead of profile for long-term monitoring:**
```bash
# Monitor streams events, doesn't accumulate in memory
sudo ./build/crypto-tracer monitor --duration 3600
```

**3. Restart periodically for long-term monitoring:**
```bash
# Monitor in 1-hour chunks
while true; do
    sudo ./build/crypto-tracer monitor --duration 3600 >> events.json
    sleep 1
done
```

### Issue: Monitored Application Slowdown

**Symptoms:**
```
# Application performance degraded while monitoring
```

**Diagnosis:**
```bash
# Check crypto-tracer overhead
top -p $(pgrep crypto-tracer)

# Check event rate
sudo ./build/crypto-tracer monitor --duration 10 --verbose
```

**Solutions:**

**1. Use more specific filters:**
```bash
# Only monitor specific files
sudo ./build/crypto-tracer files --file "/etc/ssl/certs/*"
```

**2. Increase polling interval (future enhancement)**

**3. If overhead is still high:** This may be a bug. Please report with:
- Application being monitored
- Event rate (events/second)
- System specs (CPU, RAM)

---

## Output and Formatting Issues

### Issue: Invalid JSON Output

**Symptoms:**
```
# JSON parsing fails
cat events.json | jq '.'
parse error: Invalid numeric literal at line 1, column 10
```

**Causes and Solutions:**

**1. Incomplete output (interrupted):**
```bash
# Use json-stream format (each line is valid JSON)
sudo ./build/crypto-tracer monitor --format json-stream

# Each line can be parsed independently
cat events.json | while read line; do echo "$line" | jq '.'; done
```

**2. Mixed output formats:**
```bash
# Don't mix verbose output with JSON
# Instead of:
sudo ./build/crypto-tracer monitor --verbose > events.json

# Use:
sudo ./build/crypto-tracer monitor > events.json 2> debug.log
```

### Issue: Cannot Parse json-stream with jq

**Symptoms:**
```
# jq expects single JSON object, not multiple
cat events.json | jq '.'
parse error: Expected separator between values at line 2, column 1
```

**Solution:** Process line by line:
```bash
# Parse each event separately
cat events.json | while read line; do
    echo "$line" | jq '.'
done

# Or use jq slurp mode
cat events.json | jq -s '.'

# Or use jq compact output
cat events.json | jq -c '.'
```

### Issue: Timestamps Not in Local Time

**Cause:** Timestamps are in UTC (ISO 8601 format).

**Solution:** Convert to local time:
```bash
# With jq and date
cat events.json | jq -r '.timestamp' | while read ts; do
    date -d "$ts" "+%Y-%m-%d %H:%M:%S %Z"
done

# Or use Python
cat events.json | python3 -c "
import json, sys
from datetime import datetime
for line in sys.stdin:
    event = json.loads(line)
    dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    print(dt.astimezone())
"
```

---

## Kernel Compatibility Issues

### Issue: Kernel Too Old

**Symptoms:**
```
Error: Kernel version 3.10 is too old
Minimum required: 4.15
```

**Solutions:**

**1. Upgrade kernel:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt upgrade linux-generic

# RHEL/CentOS
sudo yum update kernel
```

**2. Use newer distribution:**
- Ubuntu 20.04+ (kernel 5.4+)
- Debian 11+ (kernel 5.10+)
- RHEL 8+ (kernel 4.18+)

**3. Check current kernel:**
```bash
uname -r
```

### Issue: eBPF Not Enabled

**Symptoms:**
```
Error: eBPF support not available
CONFIG_BPF not enabled in kernel
```

**Solutions:**

**1. Check kernel config:**
```bash
# Check if eBPF is enabled
grep CONFIG_BPF /boot/config-$(uname -r)
# Should show: CONFIG_BPF=y

# Check required options
grep -E "CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_BPF_JIT" /boot/config-$(uname -r)
```

**2. Use distribution with eBPF enabled:**
Most modern distributions have eBPF enabled by default:
- Ubuntu 18.04+
- Debian 10+
- RHEL 8+
- Fedora 30+

**3. Rebuild kernel with eBPF support (advanced):**
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
```

### Issue: BTF Not Available

**Symptoms:**
```
Warning: BTF not available, using fallback vmlinux.h
```

**Impact:** Usually not a problem. CO-RE will still work with fallback headers.

**To enable BTF (optional):**
```bash
# Check if BTF is available
ls -la /sys/kernel/btf/vmlinux

# If not available, kernel needs CONFIG_DEBUG_INFO_BTF=y
# This requires kernel 5.2+ and is enabled by default in most modern distros
```

---

## Build Issues

### Issue: Compilation Errors

**Symptoms:**
```
error: unknown type name '__u64'
error: 'BPF_MAP_TYPE_RINGBUF' undeclared
```

**Solutions:**

**1. Check dependencies:**
```bash
make check-deps
```

**2. Update libbpf:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install --only-upgrade libbpf-dev

# RHEL/Fedora
sudo dnf update libbpf-devel
```

**3. Clean and rebuild:**
```bash
make clean
make
```

### Issue: Linker Errors

**Symptoms:**
```
undefined reference to `bpf_object__open'
undefined reference to `ring_buffer__new'
```

**Cause:** Missing or incompatible libbpf.

**Solutions:**

**1. Install libbpf-dev:**
```bash
sudo apt install libbpf-dev  # Ubuntu/Debian
sudo dnf install libbpf-devel  # RHEL/Fedora
```

**2. Check library path:**
```bash
ldconfig -p | grep libbpf
```

**3. Try static linking:**
```bash
make static
```

### Issue: eBPF Compilation Errors

**Symptoms:**
```
error: use of undeclared identifier 'BPF_CORE_READ'
```

**Solutions:**

**1. Install clang:**
```bash
sudo apt install clang  # Ubuntu/Debian
sudo dnf install clang  # RHEL/Fedora
```

**2. Check clang version:**
```bash
clang --version
# Minimum: clang 10+
# Recommended: clang 11+
```

**3. Update clang:**
```bash
sudo apt install clang-14  # Ubuntu/Debian
```

---

## Getting Help

If you've tried the solutions above and still have issues:

### 1. Enable Verbose Logging
```bash
sudo ./build/crypto-tracer monitor --verbose 2>&1 | tee debug.log
```

### 2. Collect System Information
```bash
# Create a system info report
cat > sysinfo.txt <<EOF
Kernel: $(uname -r)
Distribution: $(cat /etc/os-release | grep PRETTY_NAME)
libbpf version: $(dpkg -l | grep libbpf || rpm -qa | grep libbpf)
clang version: $(clang --version | head -1)
BTF available: $(ls /sys/kernel/btf/vmlinux 2>/dev/null && echo "yes" || echo "no")
Capabilities: $(getcap ./build/crypto-tracer)
EOF
cat sysinfo.txt
```

### 3. Report Issue

Include in your bug report:
- System information (from above)
- Full error message
- Steps to reproduce
- Debug log (if applicable)

**Report to:**
- GitHub Issues: https://github.com/yourusername/crypto-tracer/issues
- Include `[BUG]` in the title

### 4. Community Resources

- Documentation: https://github.com/yourusername/crypto-tracer/wiki
- Examples: See [DEMO.md](DEMO.md)
- eBPF Resources: https://ebpf.io/

---

## Quick Reference

### Common Commands

```bash
# Check if crypto-tracer works
./build/crypto-tracer snapshot

# Test with sudo
sudo ./build/crypto-tracer monitor --duration 5

# Enable verbose logging
sudo ./build/crypto-tracer monitor --verbose

# Check capabilities
getcap ./build/crypto-tracer

# Grant capabilities
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer

# Check kernel version
uname -r

# Check eBPF support
grep CONFIG_BPF /boot/config-$(uname -r)

# Check BTF support
ls -la /sys/kernel/btf/vmlinux
```

### Diagnostic Checklist

- [ ] Kernel version >= 4.15
- [ ] eBPF enabled (CONFIG_BPF=y)
- [ ] Sufficient privileges (CAP_BPF or root)
- [ ] Dependencies installed (libbpf, libelf, zlib)
- [ ] Build successful (`make`)
- [ ] eBPF programs load (`--verbose`)
- [ ] Target process uses crypto (check with `lsof`)
- [ ] Filters not too restrictive

---

**Last Updated:** November 2024  
**Version:** 1.0
