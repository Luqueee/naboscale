#!/usr/bin/env bash
# test-mesh.sh — automated end-to-end test of naboscale mesh VPN
#
# Sets up N nodes on the same machine, each with its own TUN and UDP port,
# registers them with the coord server, sends heartbeats, starts the tunnels,
# pings between them, and reports results. Cleans up on exit.
#
# Usage:
#   ./test-mesh.sh [NODE_COUNT] [BASE_PORT] [TUN_BASE] [ENDPOINT_HOST] [WAIT_BETWEEN]
#
#   NODE_COUNT     number of nodes to create (default 2)
#   BASE_PORT      first UDP port (default 51820)
#   TUN_BASE       highest TUN number; nodes get utun99, utun98, ... (default 99)
#   ENDPOINT_HOST  IP to advertise in heartbeats (default 127.0.0.1)
#   WAIT_BETWEEN   seconds to wait between starting each node (default 3)
#
# Environment overrides:
#   NAB            path to naboscale CLI binary
#   SERVER         coord server URL
#   CONFIG_BASE    base dir for node configs
#   LOG_DIR        base dir for node logs
#   KEEP_RUNNING   1 = keep nodes alive after test
set -euo pipefail

NODE_COUNT=${1:-2}
BASE_PORT=${2:-51820}
TUN_BASE=${3:-99}
ENDPOINT_HOST=${4:-127.0.0.1}
WAIT_BETWEEN=${5:-3}

NAB="${NAB:-/root/naboscale/target/release/naboscale}"
SERVER="${SERVER:-http://127.0.0.1:8080}"
CONFIG_BASE="${CONFIG_BASE:-/tmp/naboscale-test}"
LOG_DIR="${LOG_DIR:-/tmp/naboscale-test-logs}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"

if [ ! -x "$NAB" ]; then
    echo "ERROR: $NAB not found or not executable"
    echo "  build it: cd /root/naboscale && cargo build -p naboscale-cli --release"
    exit 1
fi

mkdir -p "$LOG_DIR"

NODES=()
PORTS=()
TUNS=()
IPS=()
PIDS=()

color() { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
info() { color "36" "→ $*"; }
ok()   { color "32" "✓ $*"; }
warn() { color "33" "⚠ $*"; }
err()  { color "31" "✗ $*"; }

cleanup() {
    echo
    info "cleanup"
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    sleep 0.5
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null || true
    done
    for tun in "${TUNS[@]:-}"; do
        [ -n "$tun" ] && ip link delete "$tun" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

step() { printf "\n=== %s ===\n" "$*"; }

step "resetting coord server"
mv /var/lib/naboscale/coord.sqlite /var/lib/naboscale/coord.sqlite.prev 2>/dev/null || true
systemctl restart naboscale-coord
for i in 1 2 3 4 5; do
    if wget -qO- "$SERVER/v1/health" 2>/dev/null | grep -q ok; then
        ok "coord server healthy at $SERVER"
        break
    fi
    [ "$i" = "5" ] && { err "coord server not responding after 5s"; exit 1; }
    sleep 1
done

step "setting up $NODE_COUNT nodes"
for i in $(seq 1 $NODE_COUNT); do
    N=$((i-1))
    cfg="$CONFIG_BASE-node$i"
    port=$((BASE_PORT + i - 1))
    tun="utun$((TUN_BASE - i + 1))"

    NODES[$N]=$cfg
    PORTS[$N]=$port
    TUNS[$N]=$tun

    rm -rf "$cfg"
    "$NAB" --config-dir "$cfg" init --server "$SERVER" --force > /dev/null
    "$NAB" --config-dir "$cfg" register > /dev/null
done

step "captured IPs"
for i in $(seq 0 $((NODE_COUNT-1))); do
    status=$("$NAB" --config-dir "${NODES[$i]}" status 2>&1)
    ip=$(echo "$status" | awk '/^ip:/{print $2}')
    IPS[$i]=$ip
    printf "  node%d  ip=%-15s  tun=%-8s  udp=%s:%d\n" \
        $((i+1)) "${IPS[$i]}" "${TUNS[$i]}" "$ENDPOINT_HOST" "${PORTS[$i]}"
done

step "sending heartbeats (endpoint=$ENDPOINT_HOST)"
for i in $(seq 0 $((NODE_COUNT-1))); do
    out=$("$NAB" --config-dir "${NODES[$i]}" heartbeat --endpoint "$ENDPOINT_HOST:${PORTS[$i]}" 2>&1)
    echo "  node$((i+1)): $out"
done

step "starting $NODE_COUNT nodes (staggered by ${WAIT_BETWEEN}s)"
for i in $(seq 0 $((NODE_COUNT-1))); do
    log="$LOG_DIR/node$((i+1)).log"
    nohup "$NAB" --config-dir "${NODES[$i]}" up \
        --tun "${TUNS[$i]}" --bind-port "${PORTS[$i]}" --peer-index 0 \
        > "$log" 2>&1 &
    pid=$!
    PIDS[$i]=$pid
    info "node$((i+1)) started (pid=$pid, log=$log)"
    sleep "$WAIT_BETWEEN"
done

step "waiting 10s for handshakes to settle"
sleep 10

step "pinging all pairs"
PING_OK=0
PING_FAIL=0
for i in $(seq 0 $((NODE_COUNT-1))); do
    for j in $(seq 0 $((NODE_COUNT-1))); do
        [ $i -eq $j ] && continue
        out=$(ping -c 2 -W 2 -I "${IPS[$i]}" "${IPS[$j]}" 2>&1)
        if echo "$out" | grep -q "0% packet loss"; then
            ok "node$((i+1)) -> node$((j+1))  (${IPS[$i]} -> ${IPS[$j]})"
            PING_OK=$((PING_OK + 1))
        else
            err "node$((i+1)) -> node$((j+1))  (${IPS[$i]} -> ${IPS[$j]})"
            echo "$out" | tail -3 | sed 's/^/    /'
            PING_FAIL=$((PING_FAIL + 1))
        fi
    done
done

step "summary"
echo "  nodes:      $NODE_COUNT (tun=${TUNS[*]})"
echo "  endpoint:   $ENDPOINT_HOST (what each node advertised)"
echo "  ping OK:    $PING_OK"
echo "  ping FAIL:  $PING_FAIL"
if [ "$PING_FAIL" -gt 0 ]; then
    warn "$PING_FAIL pings failed. Likely cause: single-machine routing needs source bind (-I), or handshake didn't complete."
fi

step "TUN packet counters"
for i in $(seq 0 $((NODE_COUNT-1))); do
    tx=$(ip -s link show "${TUNS[$i]}" 2>/dev/null | awk '/TX:/{getline; print $1}')
    rx=$(ip -s link show "${TUNS[$i]}" 2>/dev/null | awk '/RX:/{getline; print $1}')
    printf "  %-8s  rx=%-5s  tx=%s\n" "${TUNS[$i]}" "${rx:-0}" "${tx:-0}"
done

step "last 5 log lines per node"
for i in $(seq 0 $((NODE_COUNT-1))); do
    log="$LOG_DIR/node$((i+1)).log"
    echo "--- node$((i+1)) ---"
    tail -5 "$log" 2>/dev/null | sed 's/^/  /' || echo "  (no log)"
done

if [ "$KEEP_RUNNING" = "1" ]; then
    step "nodes still running"
    echo "  PIDs: ${PIDS[*]}"
    echo "  config dirs: ${NODES[*]}"
    echo "  manual test:"
    echo "    ping -I ${IPS[0]} ${IPS[1]}"
    echo "  cleanup manually: kill ${PIDS[*]} && ip link delete ${TUNS[*]}"
    echo
    info "Ctrl+C to cleanup now (or run with KEEP_RUNNING=0 to auto-cleanup)"
    while true; do sleep 60; done
fi
