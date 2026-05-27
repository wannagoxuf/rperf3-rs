#!/bin/bash
cd /home/wannago/work/rperf3-rs
export RUSTUP_HOME=/home/wannago/.rustup
export CARGO_HOME=/home/wannago/.cargo
export PATH="/home/wannago/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"

# Kill any existing
pkill -9 -f rperf3 2>/dev/null
sleep 1

# Start server in background, log to file
cargo run -- server --udp --port 5201 > /tmp/rperf_server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

sleep 3

# Run client
cargo run -- client 127.0.0.1 --udp --port 5201 --one-way-send --time 5 --expected-pps 100000 2>&1

# Wait for server to finish
sleep 2
echo "=== SERVER LOG ==="
cat /tmp/rperf_server.log

# Kill server
kill -9 $SERVER_PID 2>/dev/null || true
