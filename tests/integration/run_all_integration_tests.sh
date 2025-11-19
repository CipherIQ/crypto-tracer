#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Graziano Labs Corp.

# Master integration test runner
# Runs all integration tests in sequence

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_PASSED=0
TESTS_FAILED=0

echo "========================================="
echo "crypto-tracer Integration Test Suite"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Warning: Not running as root. eBPF tests will be skipped."
    echo "Run with: sudo $0"
    echo ""
    RUN_EBPF_TESTS=0
else
    RUN_EBPF_TESTS=1
fi

# Test 1: End-to-end tests (no sudo required)
echo "=== Running E2E Tests (no sudo required) ==="
if "$SCRIPT_DIR/../../build/test_e2e"; then
    echo "✓ E2E tests passed"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "✗ E2E tests failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test 2: eBPF program loading (requires sudo)
if [ "$RUN_EBPF_TESTS" -eq 1 ]; then
    echo "=== Running eBPF Loading Tests (requires sudo) ==="
    if "$SCRIPT_DIR/test_ebpf_loading.sh"; then
        echo "✓ eBPF loading tests passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "✗ eBPF loading tests failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
    
    # Test 3: Event generation (requires sudo)
    echo "=== Running Event Generation Tests (requires sudo) ==="
    if "$SCRIPT_DIR/test_event_generation.sh"; then
        echo "✓ Event generation tests passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "✗ Event generation tests failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
    
    # Test 4: Monitor events (requires sudo)
    echo "=== Running Monitor Events Test (requires sudo) ==="
    if "$SCRIPT_DIR/test_monitor_events.sh"; then
        echo "✓ Monitor events test passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "✗ Monitor events test failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
else
    echo "⊘ Skipping eBPF tests (requires sudo)"
    echo ""
fi

echo "========================================="
echo "Integration Test Summary"
echo "========================================="
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "✓ All integration tests passed!"
    exit 0
else
    echo "✗ Some integration tests failed"
    exit 1
fi
