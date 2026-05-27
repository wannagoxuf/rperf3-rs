#!/bin/bash
cd /home/wannago/work/rperf3-rs
export RUSTUP_HOME=/home/wannago/.rustup
export CARGO_HOME=/home/wannago/.cargo
export PATH="/home/wannago/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
pkill -9 -f rperf3 2>/dev/null; sleep 1
cargo run -- server --udp --port 5201 > /tmp/srv_out.log 2>&1 &
SPID=$!
echo "Server PID: $SPID"
sleep 3
cargo run -- client 127.0.0.1 --udp --port 5201 --one-way-send --time 5 --expected-pps 100000 > /tmp/cli_out.log 2>&1
sleep 1
kill -9 $SPID 2>/dev/null
echo "=== SERVER ==="
cat /tmp/srv_out.log
echo "=== CLIENT ==="
cat /tmp/cli_out.log
