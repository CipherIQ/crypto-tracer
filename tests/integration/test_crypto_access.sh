#!/bin/bash
# Test script that continuously accesses crypto files
# This keeps the process alive and actively using crypto

echo "Starting continuous crypto file access..."
echo "PID: $$"

while true; do
    # Access certificate files
    cat /etc/ssl/certs/ca-certificates.crt > /dev/null 2>&1
    
    # Small delay
    sleep 0.5
done
