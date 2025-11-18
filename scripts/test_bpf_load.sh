#!/bin/bash
# Script to test BPF program loading and capture verifier output

set -e

PROG_NAME=$1
PROG_PATH="build/${PROG_NAME}.bpf.o"

if [ -z "$PROG_NAME" ]; then
    echo "Usage: $0 <program_name>"
    echo "Example: $0 file_open_trace"
    exit 1
fi

if [ ! -f "$PROG_PATH" ]; then
    echo "Error: $PROG_PATH not found"
    exit 1
fi

echo "Testing BPF program: $PROG_NAME"
echo "Path: $PROG_PATH"
echo ""

# Try to load with bpftool and capture output
PIN_PATH="/sys/fs/bpf/test_${PROG_NAME}"

echo "Attempting to load..."
if sudo bpftool prog load "$PROG_PATH" "$PIN_PATH" 2>&1 | tee /tmp/bpf_load_${PROG_NAME}.log; then
    echo ""
    echo "✅ SUCCESS: Program loaded!"
    echo "Cleaning up..."
    sudo rm -f "$PIN_PATH"
else
    echo ""
    echo "❌ FAILED: Program rejected by verifier"
    echo "Full output saved to: /tmp/bpf_load_${PROG_NAME}.log"
    echo ""
    echo "Last 50 lines of verifier output:"
    tail -50 /tmp/bpf_load_${PROG_NAME}.log
fi
