# crypto-tracer Privileges Quick Reference

## Why Does crypto-tracer Need Special Privileges?

crypto-tracer uses eBPF (Extended Berkeley Packet Filter) to monitor system activity at the kernel level. Loading eBPF programs requires special privileges to ensure system security.

## Three Ways to Run crypto-tracer

### Option 1: Run with sudo (Simplest) ⭐

**Best for:** Quick testing, one-time use, shared systems

```bash
sudo ./build/crypto-tracer monitor
```

**Pros:**
- ✅ Works on all Linux systems
- ✅ No setup required
- ✅ Works immediately

**Cons:**
- ❌ Need to enter password each time
- ❌ Runs with full root privileges (less secure)

---

### Option 2: Grant CAP_BPF Capability (Recommended) 🔒

**Best for:** Regular use on modern systems (kernel 5.8+)

```bash
# One-time setup
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer

# Now run without sudo
./build/crypto-tracer monitor
```

**Pros:**
- ✅ Most secure (minimal privileges)
- ✅ No password needed after setup
- ✅ Works for all users on the system
- ✅ Recommended by security best practices

**Cons:**
- ❌ Only works on kernel 5.8 or later
- ⚠️ Must re-grant after rebuilding the binary

**What are these capabilities?**
- `cap_bpf` - Permission to load eBPF programs
- `cap_perfmon` - Permission to read performance monitoring events

---

### Option 3: Grant CAP_SYS_ADMIN Capability (Older Kernels) 🔧

**Best for:** Systems with kernel < 5.8

```bash
# One-time setup
sudo setcap cap_sys_admin+ep ./build/crypto-tracer

# Now run without sudo
./build/crypto-tracer monitor
```

**Pros:**
- ✅ Works on older kernels (4.15 - 5.7)
- ✅ No password needed after setup
- ✅ Works for all users on the system

**Cons:**
- ❌ Grants more privileges than necessary
- ⚠️ Must re-grant after rebuilding the binary

---

## Quick Commands

### Check Your Kernel Version
```bash
uname -r
# If >= 5.8, use Option 2 (CAP_BPF)
# If < 5.8, use Option 3 (CAP_SYS_ADMIN)
```

### Check Current Capabilities
```bash
getcap ./build/crypto-tracer

# Expected output (kernel 5.8+):
# ./build/crypto-tracer = cap_bpf,cap_perfmon+ep

# Expected output (older kernels):
# ./build/crypto-tracer = cap_sys_admin+ep

# No output means no capabilities granted
```

### Remove Capabilities
```bash
sudo setcap -r ./build/crypto-tracer
```

### Grant Capabilities After Rebuild
```bash
# After running 'make', re-grant capabilities
make
sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer
```

---

## Special Case: snapshot Command

The `snapshot` command doesn't need any special privileges because it only reads the `/proc` filesystem:

```bash
# No sudo needed!
./build/crypto-tracer snapshot
```

This works even without capabilities or sudo.

---

## Troubleshooting

### "Permission denied" Error

**Problem:**
```
Error: Permission denied
Failed to load eBPF programs: Operation not permitted
```

**Solution:** You need to either:
1. Run with `sudo`, OR
2. Grant capabilities (see options above)

### "CAP_BPF not available" Error

**Problem:**
```
Error: CAP_BPF capability not available on this kernel
```

**Solution:** Your kernel is older than 5.8. Use Option 3 (CAP_SYS_ADMIN) instead:
```bash
sudo setcap cap_sys_admin+ep ./build/crypto-tracer
```

### Capabilities Lost After Rebuild

**Problem:** After running `make`, crypto-tracer asks for sudo again.

**Explanation:** Capabilities are tied to the specific binary file. When you rebuild, a new binary is created, and you must re-grant capabilities.

**Solution:** Create a helper script:
```bash
#!/bin/bash
# build-and-grant.sh
make && sudo setcap cap_bpf,cap_perfmon+ep ./build/crypto-tracer
```

---

## Security Considerations

### Why CAP_BPF is More Secure Than sudo

When you run with `sudo`, the program has **full root access** to your entire system. With `CAP_BPF`, the program can **only**:
- Load eBPF programs (which are verified by the kernel for safety)
- Read performance monitoring data

It **cannot**:
- Modify files
- Change system configuration
- Access other users' data
- Install software
- Or do anything else that requires root

### Are eBPF Programs Safe?

Yes! eBPF programs are verified by the Linux kernel before loading. The kernel's BPF verifier ensures that programs:
- Cannot crash the system
- Cannot access invalid memory
- Cannot run infinite loops
- Cannot modify kernel data structures unsafely

This is why eBPF is considered safe for production use.

---

## Comparison Table

| Method | Security | Convenience | Kernel Requirement | Use Case |
|--------|----------|-------------|-------------------|----------|
| **sudo** | ⚠️ Full root | ⭐ Easy | Any | Quick testing |
| **CAP_BPF** | ✅ Minimal | ⭐⭐⭐ Best | 5.8+ | Regular use |
| **CAP_SYS_ADMIN** | ⚠️ Elevated | ⭐⭐ Good | 4.15+ | Older systems |

---

## Recommended Setup

### For Development (frequent rebuilds)
```bash
# Use sudo to avoid re-granting capabilities
sudo ./build/crypto-tracer monitor
```

### For Production/Regular Use (kernel 5.8+)
```bash
# One-time setup
sudo make install
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/crypto-tracer

# Daily use
crypto-tracer monitor
```

### For Production/Regular Use (kernel < 5.8)
```bash
# One-time setup
sudo make install
sudo setcap cap_sys_admin+ep /usr/bin/crypto-tracer

# Daily use
crypto-tracer monitor
```

---

## Additional Resources

- **Man page:** `man crypto-tracer` (after installation)
- **Troubleshooting:** See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **Linux capabilities:** `man capabilities`
- **eBPF security:** https://ebpf.io/

---

**Quick Decision Tree:**

```
Do you need to use crypto-tracer right now?
├─ Yes → Use sudo (Option 1)
└─ No, setting up for regular use
   └─ Check kernel version (uname -r)
      ├─ >= 5.8 → Use CAP_BPF (Option 2) ✅ Recommended
      └─ < 5.8 → Use CAP_SYS_ADMIN (Option 3)
```
