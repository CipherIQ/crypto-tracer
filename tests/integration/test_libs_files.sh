#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Graziano Labs Corp.

# Integration test for libs and files commands

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CRYPTO_TRACER="$PROJECT_ROOT/build/crypto-tracer"

echo "=== Testing libs and files commands ==="
echo ""

# Check if binary exists
if [ ! -f "$CRYPTO_TRACER" ]; then
    echo "Error: crypto-tracer binary not found at $CRYPTO_TRACER"
    exit 1
fi

# Test 1: Files command help
echo "Test 1: Files command help"
$CRYPTO_TRACER help files
echo "✅ PASS"
echo ""

# Test 2: Libs command help
echo "Test 2: Libs command help"
$CRYPTO_TRACER help libs
echo "✅ PASS"
echo ""

# Test 3: Files command with invalid arguments
echo "Test 3: Files command with invalid arguments"
if $CRYPTO_TRACER files --invalid-option 2>/dev/null; then
    echo "❌ FAIL: Should have rejected invalid option"
    exit 1
else
    echo "✅ PASS: Correctly rejected invalid option"
fi
echo ""

# Test 4: Libs command with invalid arguments
echo "Test 4: Libs command with invalid arguments"
if $CRYPTO_TRACER libs --invalid-option 2>/dev/null; then
    echo "❌ FAIL: Should have rejected invalid option"
    exit 1
else
    echo "✅ PASS: Correctly rejected invalid option"
fi
echo ""

echo "=== Basic tests complete ==="
echo ""
echo "Note: Full functional tests require sudo privileges."
echo "Run manually:"
echo "  sudo $CRYPTO_TRACER files --duration 5"
echo "  sudo $CRYPTO_TRACER libs --duration 5"
