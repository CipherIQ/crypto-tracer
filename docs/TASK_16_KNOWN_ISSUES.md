# Task 16 Known Issues: Profile Command eBPF Program Loading Failures

## Critical Issue: eBPF Programs Not Loading

### Problem Summary

The profile command implementation is complete and correct, but it cannot function properly because the underlying eBPF programs fail to load with error code -13 (EACCES - Permission Denied from BPF verifier).

### Affected Programs

The following eBPF programs fail to load:
1. **file_open_trace.bpf.c** - Cannot trace file open operations
2. **lib_load_trace.bpf.c** - Cannot trace library loading
3. **process_exec_trace.bpf.c** - Cannot trace process execution

Only these programs load successfully:
1. **process_exit_trace.bpf.c** - Process exit events ✓
2. **openssl_api_trace.bpf.c** - OpenSSL API calls (optional) ✓

### Impact

- Profile command runs but captures minimal events (only process exits)
- Cannot detect file access to certificates/keys
- Cannot detect library loading
- Cannot track process execution
- **The profile output is essentially empty/useless**

### Root Cause

The BPF verifier is rejecting the programs during load. The error `-EACCES` indicates the verifier found something it considers unsafe. This is NOT a permissions issue (we're running as root with CAP_BPF).

### Historical Context

This issue has existed since Task 15. The monitor command was marked complete even though only 2 out of 5 eBPF programs were loading. The verification document shows:
```
[INFO] Successfully loaded 2 eBPF program(s)
```

This was accepted as "working" but it means the core functionality (file and library monitoring) was never operational.

### Technical Details

**Error Output:**
```
[WARN] libbpf: libbpf: prog 'trace_do_sys_openat2': BPF program load failed: -EACCES
[WARN] libbpf: libbpf: failed to load object 'file_open_trace_bpf'
[ERROR] Failed to load eBPF program: file_open_trace (error code: -13)
```

**Verifier Rejection:**
The BPF verifier is rejecting the programs, likely due to:
1. Stack size limits (512 bytes max)
2. Complex string operations in filtering logic
3. Memory access patterns the verifier can't verify as safe
4. Instruction complexity exceeding verifier limits

### Attempted Fixes

Multiple approaches were tried:
1. ✗ Reducing buffer sizes (256→128 bytes)
2. ✗ Using per-CPU arrays instead of stack
3. ✗ Reading directly into ring buffer memory
4. ✗ Switching from kprobes to tracepoints
5. ✗ Simplifying filtering logic

None of these resolved the verifier rejection.

### What Works

The profile command implementation itself is correct:
- ✓ Process name to PID resolution
- ✓ Target process filtering
- ✓ Duration-based profiling
- ✓ Profile document generation
- ✓ JSON output formatting
- ✓ Graceful handling of process exit
- ✓ Statistics reporting
- ✓ Integration with profile_manager

**Test Evidence:**
```bash
$ sudo ./build/crypto-tracer profile --name sleep --duration 2
[INFO] Found process 'sleep' with PID 3620030
[INFO] Profiling process: sleep (PID 3620030)
[INFO] Profile duration: 2 seconds
[INFO] Profiling started
[INFO] Profile generated successfully
[INFO] Events processed: 38
[INFO] Events filtered: 38
```

The command runs successfully, but the 38 events are all filtered out because they're not from the target PID (they're system-wide process exits).

### Required Fix

To properly fix this issue requires:

1. **Deep BPF Verifier Analysis**
   - Capture full verifier log output
   - Understand exactly why each instruction is rejected
   - May require kernel debugging tools

2. **eBPF Program Redesign**
   - Simplify programs to pass verifier
   - Remove complex string operations
   - Use simpler filtering approaches
   - Possibly split into multiple smaller programs

3. **Alternative Approaches**
   - Use tracepoints instead of kprobes (if available)
   - Use perf events instead of eBPF
   - Implement user-space polling of /proc
   - Use existing tools like `bpftrace` for prototyping

### Workaround

For now, the profile command can only capture:
- Process exit events
- Basic process metadata from /proc scanner

This provides minimal value. A proper fix requires resolving the eBPF loading issues.

### Recommendation

**Do not mark Task 16 as complete** until the eBPF programs load successfully. The profile command is useless without working eBPF programs.

This same issue affects:
- Task 15 (monitor command) - Also broken
- Task 17 (snapshot command) - Will work (uses /proc only)
- Task 18 (libs/files commands) - Will be broken

### Next Steps

1. Get full BPF verifier output (requires libbpf debugging)
2. Analyze verifier rejection reasons
3. Redesign eBPF programs to pass verifier
4. Test on multiple kernel versions
5. Consider alternative monitoring approaches if eBPF proves too restrictive

## Conclusion

The profile command implementation is complete and correct, but it cannot function without working eBPF programs. This is a critical blocker that must be resolved before Task 16 can be considered complete.

**Status: BLOCKED on eBPF program loading issues**
