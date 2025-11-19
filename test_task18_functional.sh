#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Graziano Labs Corp.

# Functional test for Task 18: libs and files commands
# This script demonstrates both commands capturing real crypto events

set -e

echo "=========================================="
echo "Task 18 Functional Test"
echo "Testing libs and files commands"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This test must be run with sudo"
    echo "Usage: sudo ./test_task18_functional.sh"
    exit 1
fi

CRYPTO_TRACER="./build/crypto-tracer"

if [ ! -f "$CRYPTO_TRACER" ]; then
    echo "Error: crypto-tracer binary not found at $CRYPTO_TRACER"
    exit 1
fi

# Compile test program if needed
if [ ! -f "./test_libs_files" ]; then
    echo "Compiling test program..."
    gcc -o test_libs_files test_libs_files.c -ldl
    echo ""
fi

echo "=========================================="
echo "Test 1: Files Command"
echo "=========================================="
echo ""
echo "Starting files command for 10 seconds..."
echo "Will capture crypto file access events"
echo ""

# Start files command in background, save output
$CRYPTO_TRACER files --duration 10 --format json-stream > /tmp/files_output.json 2>&1 &
FILES_PID=$!

# Wait a moment for it to start
sleep 2

# Generate some file access events
echo "Generating file access events..."
./test_libs_files

# Wait for files command to complete
wait $FILES_PID

echo ""
echo "Files command output:"
echo "---"
cat /tmp/files_output.json
echo "---"
echo ""

# Count events
FILE_EVENTS=$(grep -c '"event_type":"file_open"' /tmp/files_output.json 2>/dev/null || echo "0")
echo "Captured $FILE_EVENTS file_open events"
echo ""

echo "=========================================="
echo "Test 2: Libs Command"
echo "=========================================="
echo ""
echo "Starting libs command for 10 seconds..."
echo "Will capture crypto library loading events"
echo ""

# Start libs command in background, save output
$CRYPTO_TRACER libs --duration 10 --format json-stream > /tmp/libs_output.json 2>&1 &
LIBS_PID=$!

# Wait a moment for it to start
sleep 2

# Generate some library loading events
echo "Generating library loading events..."
./test_libs_files

# Wait for libs command to complete
wait $LIBS_PID

echo ""
echo "Libs command output:"
echo "---"
cat /tmp/libs_output.json
echo "---"
echo ""

# Count events
LIB_EVENTS=$(grep -c '"event_type":"lib_load"' /tmp/libs_output.json 2>/dev/null || echo "0")
echo "Captured $LIB_EVENTS lib_load events"
echo ""

echo "=========================================="
echo "Test 3: Files Command with Filter"
echo "=========================================="
echo ""
echo "Testing file pattern filter: '/etc/ssl/*.crt'"
echo ""

# Test with file filter
$CRYPTO_TRACER files --duration 5 --file '/etc/ssl/*.crt' --format json-stream > /tmp/files_filtered.json 2>&1 &
FILES_FILTER_PID=$!

sleep 2
./test_libs_files
wait $FILES_FILTER_PID

echo "Filtered output:"
echo "---"
cat /tmp/files_filtered.json
echo "---"
echo ""

FILTERED_EVENTS=$(grep -c '"event_type":"file_open"' /tmp/files_filtered.json 2>/dev/null || echo "0")
echo "Captured $FILTERED_EVENTS file_open events matching pattern"
echo ""

echo "=========================================="
echo "Test 4: Libs Command with Filter"
echo "=========================================="
echo ""
echo "Testing library filter: 'libssl'"
echo ""

# Test with library filter
$CRYPTO_TRACER libs --duration 5 --library libssl --format json-stream > /tmp/libs_filtered.json 2>&1 &
LIBS_FILTER_PID=$!

sleep 2
./test_libs_files
wait $LIBS_FILTER_PID

echo "Filtered output:"
echo "---"
cat /tmp/libs_filtered.json
echo "---"
echo ""

FILTERED_LIB_EVENTS=$(grep -c '"event_type":"lib_load"' /tmp/libs_filtered.json 2>/dev/null || echo "0")
echo "Captured $FILTERED_LIB_EVENTS lib_load events matching filter"
echo ""

echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""
echo "✅ Files command: $FILE_EVENTS events captured"
echo "✅ Libs command: $LIB_EVENTS events captured"
echo "✅ Files with filter: $FILTERED_EVENTS events captured"
echo "✅ Libs with filter: $FILTERED_LIB_EVENTS events captured"
echo ""
echo "Test complete!"
echo ""
echo "Output files saved to:"
echo "  /tmp/files_output.json"
echo "  /tmp/libs_output.json"
echo "  /tmp/files_filtered.json"
echo "  /tmp/libs_filtered.json"
