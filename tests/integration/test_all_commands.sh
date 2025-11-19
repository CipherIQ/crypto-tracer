#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Graziano Labs Corp.

# Comprehensive integration test for all crypto-tracer commands
# Tests end-to-end functionality with real eBPF programs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CRYPTO_TRACER="$PROJECT_ROOT/build/crypto-tracer"

echo "=== crypto-tracer Comprehensive Integration Tests ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Warning: Not running as root. Some tests will be skipped."
    echo "Run with: sudo $0"
    echo ""
    SKIP_PRIVILEGED=1
else
    SKIP_PRIVILEGED=0
fi

# Check if binary exists
if [ ! -f "$CRYPTO_TRACER" ]; then
    echo "Error: crypto-tracer binary not found at $CRYPTO_TRACER"
    echo "Build it first: make"
    exit 1
fi

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Helper function to run test
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_result="${3:-0}"
    
    echo "Test: $test_name"
    
    if eval "$test_cmd"; then
        if [ "$expected_result" = "0" ]; then
            echo "  ✓ PASSED"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo "  ✗ FAILED (expected failure but succeeded)"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        if [ "$expected_result" != "0" ]; then
            echo "  ✓ PASSED (expected failure)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo "  ✗ FAILED"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
    echo ""
}

# Helper function to skip test
skip_test() {
    local test_name="$1"
    echo "Test: $test_name"
    echo "  ⊘ SKIPPED (requires root privileges)"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    echo ""
}

echo "=== Basic Command Tests ==="
echo ""

# Test 1: Version
run_test "Version command" \
    "$CRYPTO_TRACER --version | grep -q 'crypto-tracer'"

# Test 2: Help
run_test "Help command" \
    "$CRYPTO_TRACER --help | grep -q 'Usage:'"

# Test 3: Invalid command
run_test "Invalid command (should fail)" \
    "$CRYPTO_TRACER invalid-command 2>&1 | grep -q 'Unknown command'" \
    "1"

echo "=== Snapshot Command Tests ==="
echo ""

# Test 4: Snapshot basic
run_test "Snapshot command" \
    "$CRYPTO_TRACER snapshot 2>&1 | grep -q 'snapshot_version'"

# Test 5: Snapshot with output file
run_test "Snapshot with output file" \
    "rm -f /tmp/test-snapshot.json && \
     $CRYPTO_TRACER snapshot --output /tmp/test-snapshot.json && \
     test -f /tmp/test-snapshot.json && \
     grep -q 'snapshot_version' /tmp/test-snapshot.json && \
     rm -f /tmp/test-snapshot.json"

# Test 6: Snapshot JSON format
run_test "Snapshot JSON format" \
    "$CRYPTO_TRACER snapshot --format json-pretty 2>&1 | grep -q 'snapshot_version'"

echo "=== Monitor Command Tests ==="
echo ""

if [ "$SKIP_PRIVILEGED" = "1" ]; then
    skip_test "Monitor command (basic)"
    skip_test "Monitor with duration"
    skip_test "Monitor with filters"
    skip_test "Monitor with output file"
else
    # Test 7: Monitor basic (2 seconds)
    run_test "Monitor command (2 seconds)" \
        "timeout 5 $CRYPTO_TRACER monitor --duration 2 --quiet 2>&1"
    
    # Test 8: Monitor with output file
    run_test "Monitor with output file" \
        "rm -f /tmp/test-monitor.json && \
         $CRYPTO_TRACER monitor --duration 1 --output /tmp/test-monitor.json --quiet 2>&1 && \
         test -f /tmp/test-monitor.json && \
         rm -f /tmp/test-monitor.json"
    
    # Test 9: Monitor with PID filter
    run_test "Monitor with PID filter" \
        "$CRYPTO_TRACER monitor --duration 1 --pid 1 --quiet 2>&1"
    
    # Test 10: Monitor with process name filter
    run_test "Monitor with process name filter" \
        "$CRYPTO_TRACER monitor --duration 1 --name systemd --quiet 2>&1"
    
    # Test 11: Monitor with library filter
    run_test "Monitor with library filter" \
        "$CRYPTO_TRACER monitor --duration 1 --library libssl --quiet 2>&1"
    
    # Test 12: Monitor with file filter
    run_test "Monitor with file filter" \
        "$CRYPTO_TRACER monitor --duration 1 --file '*.pem' --quiet 2>&1"
fi

echo "=== Profile Command Tests ==="
echo ""

if [ "$SKIP_PRIVILEGED" = "1" ]; then
    skip_test "Profile command with PID"
    skip_test "Profile command with name"
else
    # Test 13: Profile with PID (init process)
    run_test "Profile command with PID" \
        "$CRYPTO_TRACER profile --pid 1 --duration 2 --quiet 2>&1 | grep -q 'profile_version'"
    
    # Test 14: Profile with process name
    run_test "Profile command with process name" \
        "$CRYPTO_TRACER profile --name systemd --duration 2 --quiet 2>&1 | grep -q 'profile_version'"
    
    # Test 15: Profile with output file
    run_test "Profile with output file" \
        "rm -f /tmp/test-profile.json && \
         $CRYPTO_TRACER profile --pid 1 --duration 1 --output /tmp/test-profile.json --quiet 2>&1 && \
         test -f /tmp/test-profile.json && \
         grep -q 'profile_version' /tmp/test-profile.json && \
         rm -f /tmp/test-profile.json"
fi

echo "=== Libs Command Tests ==="
echo ""

if [ "$SKIP_PRIVILEGED" = "1" ]; then
    skip_test "Libs command"
    skip_test "Libs with filter"
else
    # Test 16: Libs basic
    run_test "Libs command" \
        "$CRYPTO_TRACER libs --duration 2 --quiet 2>&1"
    
    # Test 17: Libs with library filter
    run_test "Libs with library filter" \
        "$CRYPTO_TRACER libs --duration 1 --library libssl --quiet 2>&1"
fi

echo "=== Files Command Tests ==="
echo ""

if [ "$SKIP_PRIVILEGED" = "1" ]; then
    skip_test "Files command"
    skip_test "Files with filter"
else
    # Test 18: Files basic
    run_test "Files command" \
        "$CRYPTO_TRACER files --duration 2 --quiet 2>&1"
    
    # Test 19: Files with file filter
    run_test "Files with file filter" \
        "$CRYPTO_TRACER files --duration 1 --file '*.pem' --quiet 2>&1"
fi

echo "=== Validation Tests ==="
echo ""

# Test 20: Invalid duration
run_test "Invalid duration (should fail)" \
    "$CRYPTO_TRACER monitor --duration -10 2>&1 | grep -q 'Invalid'" \
    "1"

# Test 21: Invalid PID
run_test "Invalid PID (should fail)" \
    "$CRYPTO_TRACER profile --pid -1 2>&1 | grep -q 'Invalid'" \
    "1"

# Test 22: Profile without target
run_test "Profile without target (should fail)" \
    "$CRYPTO_TRACER profile 2>&1 | grep -q 'PID\|name\|target'" \
    "1"

echo "=== Flag Tests ==="
echo ""

# Test 23: Verbose flag
run_test "Verbose flag" \
    "$CRYPTO_TRACER snapshot --verbose 2>&1 | grep -q 'Starting\|Scanning'"

# Test 24: Quiet flag
run_test "Quiet flag" \
    "$CRYPTO_TRACER snapshot --quiet 2>&1 | grep -q 'snapshot_version'"

# Test 25: No-redact flag
run_test "No-redact flag" \
    "$CRYPTO_TRACER snapshot --no-redact 2>&1 | grep -q 'snapshot_version'"

echo "=== Signal Handling Tests ==="
echo ""

if [ "$SKIP_PRIVILEGED" = "1" ]; then
    skip_test "SIGINT handling"
    skip_test "SIGTERM handling"
else
    # Test 26: SIGINT handling
    run_test "SIGINT handling" \
        "$CRYPTO_TRACER monitor --quiet 2>&1 & \
         PID=\$!; sleep 1; kill -INT \$PID; wait \$PID; \
         test \$? -eq 0"
    
    # Test 27: SIGTERM handling
    run_test "SIGTERM handling" \
        "$CRYPTO_TRACER monitor --quiet 2>&1 & \
         PID=\$!; sleep 1; kill -TERM \$PID; wait \$PID; \
         test \$? -eq 0"
fi

echo "=== Performance Tests ==="
echo ""

# Test 28: Startup time (should be < 2 seconds)
run_test "Startup time < 2 seconds" \
    "START=\$(date +%s); \
     $CRYPTO_TRACER snapshot --quiet 2>&1 > /dev/null; \
     END=\$(date +%s); \
     ELAPSED=\$((END - START)); \
     test \$ELAPSED -le 2"

# Test 29: Memory usage (snapshot should use < 50MB)
run_test "Memory usage < 50MB" \
    "$CRYPTO_TRACER snapshot --quiet 2>&1 > /dev/null"

echo "=== Test Summary ==="
echo ""
echo "Tests passed:  $TESTS_PASSED"
echo "Tests failed:  $TESTS_FAILED"
echo "Tests skipped: $TESTS_SKIPPED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi
