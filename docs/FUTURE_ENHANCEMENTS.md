# Future Enhancements

This document tracks features that are planned but deferred to future releases.

## 1. Child Process Tracking (--follow-children)

**Status:** Framework implemented, functionality deferred  
**Priority:** Medium  
**Complexity:** Medium  
**Related Requirement:** 2.4

### Description
The `--follow-children` flag is currently accepted by the profile command but does not track child processes. When a target process spawns child processes, events from those children are filtered out.

### Current Behavior
```bash
# Parent process (PID 1234) spawns child (PID 1235)
sudo ./crypto-tracer profile --pid 1234 --follow-children

# Result: Only events from PID 1234 are captured
# Events from PID 1235 are filtered out
```

### Desired Behavior
```bash
# Parent process (PID 1234) spawns child (PID 1235)
sudo ./crypto-tracer profile --pid 1234 --follow-children

# Result: Events from both PID 1234 and PID 1235 are captured
# Profile includes all crypto operations from parent and children
```

### Implementation Approach

#### 1. Track Process Exec Events
Monitor `process_exec` events to detect when target process spawns children:

```c
// In profile_event_callback
if (event->event_type == EVENT_PROCESS_EXEC && event->ppid == target_pid) {
    // Add child PID to tracking set
    add_tracked_pid(pctx, event->pid);
    log_debug("Tracking child process: PID %d (parent: %d)", 
              event->pid, event->ppid);
}
```

#### 2. Maintain Tracked PID Set
Use a hash set to track parent + all children:

```c
typedef struct {
    pid_t *pids;
    size_t count;
    size_t capacity;
} pid_set_t;

// Check if PID is tracked
bool is_tracked_pid(pid_set_t *set, pid_t pid) {
    for (size_t i = 0; i < set->count; i++) {
        if (set->pids[i] == pid) {
            return true;
        }
    }
    return false;
}
```

#### 3. Update Event Filtering
Modify PID matching logic:

```c
// Current (single PID)
bool matches_target = (event->pid == pctx->target_pid);

// Enhanced (parent + children)
bool matches_target = (event->pid == pctx->target_pid) ||
                      (pctx->follow_children && 
                       is_tracked_pid(&pctx->tracked_pids, event->pid));
```

#### 4. Handle Process Exits
Remove PIDs from tracking set when processes exit:

```c
// In profile_event_callback
if (event->event_type == EVENT_PROCESS_EXIT) {
    if (is_tracked_pid(&pctx->tracked_pids, event->pid)) {
        remove_tracked_pid(pctx, event->pid);
        log_debug("Child process exited: PID %d", event->pid);
    }
}
```

### Testing Strategy

#### Test Case 1: Shell Script Spawning Commands
```bash
# test_with_children.sh
#!/bin/bash
while true; do
    cat /etc/ssl/certs/ca-certificates.crt > /dev/null
    sleep 1
done
```

Expected: Capture events from both bash and cat processes

#### Test Case 2: Fork/Exec Pattern
```c
// test_fork_exec.c
int main() {
    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child: access crypto file
            int fd = open("/etc/ssl/certs/ca-certificates.crt", O_RDONLY);
            close(fd);
            exit(0);
        }
        wait(NULL);
    }
}
```

Expected: Capture events from parent and all 5 children

#### Test Case 3: Deep Process Tree
```
parent (PID 1000)
  └─ child1 (PID 1001)
      └─ grandchild (PID 1002)
```

Expected: Capture events from all three processes

### Edge Cases to Handle

1. **Race Condition:** Child spawns before we start tracking
   - Solution: Scan /proc/PID/task at startup to find existing children
   
2. **PID Reuse:** Kernel reuses PIDs after process exits
   - Solution: Remove PID from tracking set on process_exit event
   
3. **Orphaned Children:** Parent exits, children continue
   - Solution: Continue tracking children until they exit
   
4. **Deep Process Trees:** Grandchildren, great-grandchildren, etc.
   - Solution: Track all descendants recursively

### Performance Considerations

- **Memory:** Each tracked PID adds 4 bytes to tracking set
- **CPU:** PID lookup is O(n) where n = number of tracked processes
- **Optimization:** Use hash table instead of array for large process trees

### Documentation Updates Needed

- Update `--help` text to explain child process tracking
- Add examples to README showing use cases
- Document limitations (e.g., race conditions at startup)
- Update verification tests

### Estimated Effort
- Implementation: 4-6 hours
- Testing: 2-3 hours
- Documentation: 1-2 hours
- **Total: 7-11 hours**

---

## 2. Uprobe-Based Library Tracing

**Status:** Not implemented  
**Priority:** Low  
**Complexity:** High  
**Related Programs:** lib_load_trace, openssl_api_trace

### Description
Uprobe-based tracing for dlopen() and OpenSSL API calls currently fails to attach due to missing function path specifications.

### Current Error
```
[WARN] libbpf: prog 'trace_dlopen': section 'uprobe/dlopen' missing ':function[+offset]' specification
[WARN] libbpf: prog 'trace_dlopen': failed to auto-attach: -EINVAL
```

### Implementation Approach
Use manual uprobe attachment with explicit library paths:

```c
struct bpf_link *link = bpf_program__attach_uprobe(
    prog,
    false,  // not uretprobe
    -1,     // any process
    "/lib/x86_64-linux-gnu/libc.so.6",
    "dlopen"
);
```

### Challenges
- Library paths vary by distribution
- Need to detect library locations at runtime
- Multiple library versions may exist
- Architecture-specific paths (x86_64, aarch64, etc.)

---

## 3. Real-Time Timestamp Correction

**Status:** Known issue  
**Priority:** Low  
**Complexity:** Low

### Description
Timestamps currently show epoch 1970 dates instead of current time.

### Current Behavior
```json
{"timestamp": "1970-01-27T10:28:56.577486Z"}
```

### Desired Behavior
```json
{"timestamp": "2025-11-18T21:55:44.000000Z"}
```

### Implementation
Convert from monotonic clock to wall clock time:

```c
// Get boot time offset
struct timespec boot_time;
clock_gettime(CLOCK_BOOTTIME, &boot_time);

// Convert event timestamp
uint64_t wall_time_ns = event->timestamp_ns + boot_time_offset;
```

---

## 4. Advanced Filtering Options

**Status:** Not planned  
**Priority:** Low  
**Complexity:** Medium

### Potential Features
- Regex pattern matching for file paths
- Multiple PID targeting (comma-separated list)
- UID/GID filtering
- Time-based filtering (only capture during specific hours)
- Rate limiting (max events per second)

---

## 5. Output Format Enhancements

**Status:** Not planned  
**Priority:** Low  
**Complexity:** Low

### Potential Features
- CSV output format
- SQLite database output
- Syslog integration
- Real-time streaming to remote server
- Compression for large outputs

---

## Contributing

If you'd like to implement any of these enhancements, please:
1. Open an issue to discuss the approach
2. Reference this document in your PR
3. Update this document when feature is completed
4. Add comprehensive tests
5. Update user documentation

## Priority Definitions

- **High:** Critical for core functionality
- **Medium:** Valuable but not blocking
- **Low:** Nice to have, quality of life improvement
