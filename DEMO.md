# crypto-tracer Demo - Realistic Usage Scenarios

## Scenario 1: Monitor System-Wide Crypto Activity (2 terminals)

### Terminal 1: Start the monitor
```bash
# Monitor all crypto activity for 60 seconds (pretty format for easy viewing)
sudo ./build/crypto-tracer monitor --duration 60 --format json-pretty
```

### Terminal 2: Generate crypto activity
```bash
# Access various crypto files
cat /etc/ssl/certs/ca-certificates.crt > /dev/null
openssl version
openssl list -digest-algorithms
curl -I https://github.com 2>/dev/null | head -5

# Check if any services are using crypto
ps aux | grep -E "(nginx|apache|ssh)" | head -5
```

**What you'll see**: Real-time JSON events showing file_open events for certificates, library loads, and process activity.

**Tip**: Use `json-pretty` format for human-readable output, or `json-stream` for machine processing.

---

## Scenario 2: Profile a Specific Application (3 terminals)

### Terminal 1: Start crypto-tracer in profile mode
```bash
# We'll profile curl accessing HTTPS sites
# First, get curl's PID (we'll start it in Terminal 2)
sudo ./build/crypto-tracer profile --name curl --duration 30
```

### Terminal 2: Run the application being profiled
```bash
# Make several HTTPS requests
for i in {1..5}; do
    curl -s https://github.com > /dev/null
    sleep 2
done
```

### Terminal 3: Watch what's happening
```bash
# See curl processes
watch -n 1 'ps aux | grep curl | grep -v grep'
```

**What you'll see**: A complete profile JSON document showing all crypto files accessed by curl, libraries loaded, and statistics.

---

## Scenario 3: Snapshot Current Crypto Usage (1 terminal, no sudo!)

```bash
# Take a snapshot of all processes using crypto (no sudo needed!)
./build/crypto-tracer snapshot | python3 -m json.tool | less

# Or save it to a file
./build/crypto-tracer snapshot --output crypto-inventory.json

# View the summary
cat crypto-inventory.json | python3 -m json.tool | grep -A 5 "summary"
```

**What you'll see**: Complete inventory of all processes currently using crypto libraries or files.

---

## Scenario 4: Monitor Specific Crypto Files (2 terminals)

### Terminal 1: Monitor only certificate access
```bash
sudo ./build/crypto-tracer monitor --duration 60 --file "*.pem" --format json-stream
```

### Terminal 2: Access various certificates
```bash
# Access different certificate types
for cert in /etc/ssl/certs/*.pem; do
    head -1 "$cert" > /dev/null 2>&1
    sleep 0.5
done | head -20
```

**What you'll see**: Filtered events showing only .pem file access with file type classification.

---

## Scenario 5: Profile Your Own Test Program (2 terminals)

### Terminal 1: Compile and run the test program
```bash
# Use our crypto activity generator
gcc -o /tmp/crypto_test tests/integration/crypto_activity_generator.c
/tmp/crypto_test 30  # Run for 30 seconds
```

### Terminal 2: Profile it
```bash
# Get the PID from Terminal 1 output, then:
sudo ./build/crypto-tracer profile --pid <PID> --duration 25 | python3 -m json.tool
```

**What you'll see**: Detailed profile showing exactly which crypto files were accessed, how many times, and when.

---

## Scenario 6: Real-World Web Server Monitoring (2 terminals)

### Terminal 1: Monitor nginx/apache (if installed)
```bash
# Find nginx/apache PID
ps aux | grep -E "nginx|apache" | grep -v grep

# Profile the web server
sudo ./build/crypto-tracer profile --name nginx --duration 60
# OR
sudo ./build/crypto-tracer profile --name apache2 --duration 60
```

### Terminal 2: Generate HTTPS traffic
```bash
# If you have a local web server with HTTPS:
for i in {1..10}; do
    curl -k https://localhost > /dev/null 2>&1
    sleep 2
done
```

**What you'll see**: Profile showing SSL/TLS certificate access by the web server.

---

## Scenario 7: Compare Privacy Filtering (1 terminal)

```bash
# Create a test file in your home directory
touch ~/my-secret-key.pem

# Monitor with privacy filtering (default)
sudo ./build/crypto-tracer monitor --duration 5 &
MONITOR_PID=$!
sleep 1
cat ~/my-secret-key.pem > /dev/null 2>&1
wait $MONITOR_PID

echo "---"

# Monitor WITHOUT privacy filtering
sudo ./build/crypto-tracer monitor --duration 5 --no-redact &
MONITOR_PID=$!
sleep 1
cat ~/my-secret-key.pem > /dev/null 2>&1
wait $MONITOR_PID

# Cleanup
rm ~/my-secret-key.pem
```

**What you'll see**: First run shows `/home/USER/my-secret-key.pem`, second shows actual username.

---

## Scenario 8: Monitor SSH Activity (2 terminals)

### Terminal 1: Monitor SSH-related crypto
```bash
sudo ./build/crypto-tracer monitor --duration 60 --name ssh
```

### Terminal 2: Generate SSH activity
```bash
# Check SSH keys
ls -la ~/.ssh/
cat ~/.ssh/id_rsa.pub 2>/dev/null || echo "No SSH key found"

# Or try SSH connection (will fail but generates crypto activity)
ssh -o ConnectTimeout=2 localhost 2>&1 | head -5
```

**What you'll see**: SSH accessing its crypto keys and certificates.

---

## Scenario 9: Libs Command - Find All Crypto Libraries (1 terminal)

```bash
# Monitor for crypto library loads for 30 seconds
sudo ./build/crypto-tracer libs --duration 30 &
LIBS_PID=$!

# Generate some activity
openssl version
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
curl -I https://github.com 2>/dev/null | head -3

wait $LIBS_PID
```

**What you'll see**: Events showing when libssl, libcrypto, etc. are loaded.

---

## Scenario 10: Files Command - Track Certificate Access (2 terminals)

### Terminal 1: Monitor certificate file access
```bash
sudo ./build/crypto-tracer files --duration 30 --file "*.crt"
```

### Terminal 2: Access various certificates
```bash
# Access system certificates
for cert in /etc/ssl/certs/*.crt; do
    file "$cert"
    sleep 1
done | head -10
```

**What you'll see**: Real-time tracking of which .crt files are being accessed.

---

## Viewing JSON Output - Best Practices

### Understanding Output Formats

crypto-tracer has three JSON output formats:

1. **json-stream** (default): One JSON object per line - best for real-time processing
2. **json-pretty**: Pretty-printed JSON array - best for human viewing
3. **json-array**: Compact JSON array - best for machine processing

### How to View Each Format

#### For json-stream format (one JSON per line):
```bash
# View raw (cleanest)
cat /tmp/crypto-events.json | less

# Pretty-print each event separately
cat /tmp/crypto-events.json | while read line; do 
    echo "$line" | python3 -m json.tool
    echo "---"
done | less

# Extract specific fields (if jq installed)
cat /tmp/crypto-events.json | jq -r '[.event_type, .process, .file] | @tsv' | column -t

# Count event types
cat /tmp/crypto-events.json | jq -r '.event_type' | sort | uniq -c
```

#### For json-pretty or json-array format:
```bash
# These are already formatted or can be piped directly
cat /tmp/crypto-events.json | less

# Or with python
cat /tmp/crypto-events.json | python3 -m json.tool | less
```

### Recommended: Use json-pretty for demos
```bash
# Best for viewing - outputs pretty JSON directly
sudo ./build/crypto-tracer monitor --duration 10 --format json-pretty

# Save and view later
sudo ./build/crypto-tracer monitor --duration 10 --format json-pretty > /tmp/events.json
less /tmp/events.json
```

### Bonus: jq Power Commands

If you have `jq` installed, you can do powerful filtering:

```bash
# Snapshot with pretty colors
./build/crypto-tracer snapshot | jq '.'

# Monitor with selective fields (use json-stream format)
sudo ./build/crypto-tracer monitor --duration 10 --format json-stream | \
    jq '{event: .event_type, process: .process, file: .file}'

# Profile with statistics only
sudo ./build/crypto-tracer profile --pid $$ --duration 5 | jq '.statistics'

# Filter only certificate files
sudo ./build/crypto-tracer monitor --duration 10 --format json-stream | \
    jq 'select(.file_type == "certificate")'

# Group events by process
sudo ./build/crypto-tracer monitor --duration 10 --format json-stream | \
    jq -s 'group_by(.process) | map({process: .[0].process, count: length})'
```

---

## Quick Demo Script (All-in-One)

```bash
#!/bin/bash
echo "=== crypto-tracer Demo ==="
echo ""

echo "1. Taking system snapshot..."
./build/crypto-tracer snapshot | python3 -m json.tool | head -30
echo ""

echo "2. Monitoring for 5 seconds while generating activity..."
sudo ./build/crypto-tracer monitor --duration 5 &
MONITOR_PID=$!
sleep 1
cat /etc/ssl/certs/ca-certificates.crt > /dev/null
openssl version > /dev/null
wait $MONITOR_PID
echo ""

echo "3. Profiling crypto activity generator..."
./tests/integration/crypto_activity_generator 5 > /dev/null 2>&1 &
GEN_PID=$!
sleep 0.5
sudo ./build/crypto-tracer profile --pid $GEN_PID --duration 4 | python3 -m json.tool
wait $GEN_PID
echo ""

echo "Demo complete!"
```

Save this as `demo.sh`, make it executable (`chmod +x demo.sh`), and run it!

---

## Tips for Best Results

1. **Use `--format json-pretty`** for human-readable output (best for demos!)
2. **Use `--format json-stream`** for machine processing with jq/scripts
3. **Run monitor in background** with `&` to generate activity in the same terminal
4. **Use `--verbose`** to see what's happening under the hood
5. **Redirect to file** with `--output` or `>` to analyze later
6. **Use filters** (`--pid`, `--name`, `--library`, `--file`) to focus on specific activity
7. **Don't pipe json-stream to `python3 -m json.tool`** - it expects one JSON object, not multiple
8. **Use `jq` for powerful filtering** if you have it installed

## 🌟 Most Impressive Demo (Recommended!)

### Option A: Live Pretty Output (Easiest)

```bash
# Terminal 1: Start monitor with pretty output
sudo ./build/crypto-tracer monitor --duration 30 --format json-pretty

# Terminal 2: Generate diverse crypto activity
for i in {1..5}; do
    curl -s https://github.com > /dev/null
    openssl rand -base64 32 > /dev/null
    cat /etc/ssl/certs/ca-certificates.crt > /dev/null
    sleep 2
done
```

**What you'll see**: Beautiful, formatted JSON showing real-time crypto events!

### Option B: Save and Analyze Later

```bash
# Terminal 1: Save to file
sudo ./build/crypto-tracer monitor --duration 30 --format json-pretty > /tmp/crypto-events.json

# Terminal 2: Generate activity
for i in {1..5}; do
    curl -s https://github.com > /dev/null
    openssl rand -base64 32 > /dev/null
    cat /etc/ssl/certs/*.pem 2>/dev/null | head -100 > /dev/null
    sleep 2
done

# Then view the results
less /tmp/crypto-events.json
```

### Option C: Stream Processing (Advanced)

```bash
# Terminal 1: Stream format for processing
sudo ./build/crypto-tracer monitor --duration 30 --format json-stream | tee /tmp/crypto-events.json

# Terminal 2: Generate activity (same as above)

# Then analyze with jq
cat /tmp/crypto-events.json | jq -r '.event_type' | sort | uniq -c
cat /tmp/crypto-events.json | jq 'select(.file_type == "certificate") | .file' | sort -u
```

This will show a rich stream of crypto events with real-world activity!
