#!/bin/bash
# verify_core.sh - Verify CO-RE strategy implementation
# Copyright (C) 2024

set -e

echo "=== Verifying CO-RE Strategy Implementation ==="

# Test 1: vmlinux.h generation
echo "1. Testing vmlinux.h generation..."
make build/vmlinux.h >/dev/null 2>&1

if [ -f "build/vmlinux.h" ]; then
    echo "   ✓ vmlinux.h generated successfully"
    
    # Check if it's the fallback or real BTF
    if grep -q "vmlinux_fallback.h" build/vmlinux.h; then
        echo "   ℹ Using fallback vmlinux.h (no BTF support)"
    else
        echo "   ✓ Using BTF-generated vmlinux.h"
    fi
else
    echo "   ✗ Failed to generate vmlinux.h"
    exit 1
fi

# Test 2: Verify eBPF programs include correct headers
echo "2. Testing eBPF program headers..."
for bpf_file in src/ebpf/*.bpf.c; do
    if grep -q '#include "vmlinux.h"' "$bpf_file"; then
        echo "   ✓ $(basename "$bpf_file") includes vmlinux.h"
    else
        echo "   ✗ $(basename "$bpf_file") missing vmlinux.h include"
        exit 1
    fi
    
    if grep -q '#include <bpf/bpf_core_read.h>' "$bpf_file"; then
        echo "   ✓ $(basename "$bpf_file") includes bpf_core_read.h"
    else
        echo "   ✗ $(basename "$bpf_file") missing bpf_core_read.h include"
        exit 1
    fi
done

# Test 3: Verify Makefile CO-RE configuration
echo "3. Testing Makefile CO-RE configuration..."
if grep -q "btf dump file" Makefile; then
    echo "   ✓ Makefile configured for BTF extraction"
else
    echo "   ✗ Makefile missing BTF extraction"
    exit 1
fi

if grep -q "vmlinux_fallback.h" Makefile; then
    echo "   ✓ Makefile configured for fallback strategy"
else
    echo "   ✗ Makefile missing fallback strategy"
    exit 1
fi

# Test 4: Verify skeleton generation setup
echo "4. Testing skeleton generation setup..."
if grep -q "gen skeleton" Makefile; then
    echo "   ✓ Makefile configured for skeleton generation"
else
    echo "   ✗ Makefile missing skeleton generation"
    exit 1
fi

if grep -q "\.skel\.h" Makefile; then
    echo "   ✓ Makefile handles skeleton headers"
else
    echo "   ✗ Makefile missing skeleton header handling"
    exit 1
fi

# Test 5: Verify static linking option
echo "5. Testing static linking configuration..."
if grep -q "ifdef STATIC" Makefile; then
    echo "   ✓ Static linking option available"
else
    echo "   ✗ Static linking option missing"
    exit 1
fi

echo ""
echo "=== CO-RE Strategy Verification Complete ==="
echo "✓ All CO-RE components properly configured"
echo ""
echo "Summary:"
echo "- vmlinux.h: Auto-generation with fallback ✓"
echo "- BPF_CORE_READ: Headers included ✓"  
echo "- Skeleton generation: Configured ✓"
echo "- Static linking: Available ✓"
echo "- Build system: Complete ✓"