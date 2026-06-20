#!/usr/bin/env bash
# deploy-mesh.sh — zero-config 2-machine mesh deploy + ping test
#
# SIMPLEST USE:
#   1. echo 'HOST_A=10.0.0.1'  > scripts/.deploy.conf
#   2. echo 'HOST_B=10.0.0.2' >> scripts/.deploy.conf
#   3. ./scripts/deploy-mesh.sh
#
# If HOST_B is 127.0.0.1 / localhost, node 2 runs on THIS machine
# (macOS or Linux) without SSH. Perfect for Mac ↔ VPN setups.
#
# All flags optional. Config priority: CLI flags > env vars > .deploy.conf > defaults.

set -euo pipefail
cd "$(dirname "$0")/.."

# ── load config ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$SCRIPT_DIR/.deploy.conf" ] && { set -a; source "$SCRIPT_DIR/.deploy.conf"; set +a; }

HOST_A="${DEPLOY_A:-${HOST_A:-}}"
HOST_B="${DEPLOY_B:-${HOST_B:-}}"
SSH_USER="${DEPLOY_SSH_USER:-${SSH_USER:-root}}"
COORD_PORT="${DEPLOY_COORD_PORT:-${COORD_PORT:-8080}}"
MESH_PORT="${DEPLOY_MESH_PORT:-${MESH_PORT:-51820}}"
PASSPHRASE="${DEPLOY_PASSPHRASE:-${PASSPHRASE:-mesh-deploy-$(date +%s)}}"
BUILD="${DEPLOY_BUILD:-${BUILD:-1}}"
KEEP="${DEPLOY_KEEP:-${KEEP:-0}}"

while [ $# -gt 0 ]; do
    case "$1" in
        --a) HOST_A="$2"; shift 2 ;;   --b) HOST_B="$2"; shift 2 ;;
        --user) SSH_USER="$2"; shift 2 ;;
        --no-build) BUILD=0; shift ;;   --keep) KEEP=1; shift ;;
        -h|--help)
            echo "usage: $0 [--a HOST] [--b HOST] [--user USER] [--no-build] [--keep]"
            echo "  Zero-config: put HOST_A=... HOST_B=... in scripts/.deploy.conf"
            echo "  Or: DEPLOY_A=... DEPLOY_B=... $0"
            echo "  If HOST_B=127.0.0.1: node 2 runs locally (no SSH)."
            exit 0 ;;
        *) echo "unknown: $1"; exit 2 ;;
    esac
done

if [ -z "$HOST_A" ] || [ -z "$HOST_B" ]; then
    echo "  Need two machines. Create scripts/.deploy.conf:"
    echo "    HOST_A=<vpn-or-server-ip>"
    echo "    HOST_B=<other-machine-ip-or-127.0.0.1-for-local>"
    echo "  Or: DEPLOY_A=... DEPLOY_B=... $0"
    exit 1
fi

# ── helpers ─────────────────────────────────────────────────────────────
c()    { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
ok()   { c "32" "  ✓ $*"; }
err()  { c "31" "  ✗ $*"; }
info() { c "36" "  → $*"; }
hdr()  { printf "\n\033[1;34m═══ %s ═══\033[0m\n" "$*"; }
sshq() { ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "$SSH_USER@$1" "${@:2}"; }
scpq() { scp -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "$2" "$SSH_USER@$1:$3"; }

is_local() {
    case "$1" in 127.0.0.1|localhost|::1|"$(hostname)"|"$(hostname -s)") return 0 ;; esac
    # Check if this IP belongs to any local interface
    { ifconfig 2>/dev/null || ip -4 addr show 2>/dev/null; } | grep -qF "$1" && return 0
    return 1
}

# run_on HOST "cmd" — runs locally if HOST is this machine, else via SSH
run_on() {
    local host="$1"; shift
    if is_local "$host"; then bash -c "$@"; else sshq "$host" bash -s <<< "$@"; fi
}

# run_on_bg HOST "cmd" — background variant
run_on_bg() {
    local host="$1"; shift
    if is_local "$host"; then bash -c "$@" & else sshq "$host" bash -s <<< "$@" & fi
}

# copy_bin HOST src dst — copies locally or via scp
copy_bin() {
    if is_local "$1"; then cp "$2" "$3"; else scpq "$1" "$2" "$3"; fi
}

cleanup() {
    echo; info "cleanup"
    run_on "$HOST_A" "pkill -f 'naboscale.*node1' 2>/dev/null; ip link del utun99 2>/dev/null" &
    # On macOS, TUN needs sudo to destroy.
    if is_local "$HOST_B"; then
        sudo -n pkill -f 'naboscale.*node2' 2>/dev/null || true
        sudo -n ifconfig utun99 destroy 2>/dev/null || true
        sudo -n pkill -f "naboscale.*$NODE2_DIR" 2>/dev/null || true
    else
        run_on "$HOST_B" "pkill -f 'naboscale.*node2' 2>/dev/null; ip link del utun99 2>/dev/null" &
    fi
    wait
}
[ "$KEEP" = "0" ] && trap cleanup EXIT INT TERM

COORD_URL="http://${HOST_A}:${COORD_PORT}"
NODE1_DIR="/etc/naboscale/node1"
# On macOS (local), /etc/ needs root. Use /tmp for the local node.
if is_local "$HOST_B" && [ "$(uname -s)" = "Darwin" ]; then
    NODE2_DIR="/tmp/naboscale-test/node2"
    # Pre-warm sudo so the background tunnel start doesn't block.
    if ! sudo -n true 2>/dev/null; then
        echo "  macOS TUN device needs root. Enter sudo password now."
        sudo -v
        # Keep sudo alive in background
        (while true; do sudo -n true; sleep 60; done) &
        SUDO_KEEPER=$!
        trap "kill \$SUDO_KEEPER 2>/dev/null" EXIT
    fi
else
    NODE2_DIR="/etc/naboscale/node2"
fi

# ── detect target arch + binary paths ───────────────────────────────────
LOCAL_OS="$(uname -s)"
LOCAL_ARCH="$(uname -m)"
REMOTE_OS="$(sshq "$HOST_A" 'uname -s' 2>/dev/null || echo Linux)"
REMOTE_ARCH="$(sshq "$HOST_A" 'uname -m' 2>/dev/null || echo x86_64)"

NAB_LOCAL="$PWD/target/release/naboscale"
NAB_REMOTE="$PWD/target/release/naboscale"
NAB_COORD="$PWD/target/release/naboscale-coord"

CROSS_COMPILE=0
if [ "$LOCAL_OS" = "Darwin" ] && [ "$REMOTE_OS" = "Linux" ]; then
    CROSS_COMPILE=1
    RUST_TARGET="${REMOTE_ARCH}-unknown-linux-gnu"
    XTARGET_DIR="$PWD/target/$RUST_TARGET/release"
    NAB_REMOTE="$XTARGET_DIR/naboscale"
    NAB_COORD="$XTARGET_DIR/naboscale-coord"
fi

# ── build ───────────────────────────────────────────────────────────────
if [ "$BUILD" = "1" ]; then
    hdr "build"
    # Always build natively for local use first.
    cargo build --workspace --release --quiet 2>&1 | tail -2
    if [ "$CROSS_COMPILE" = "1" ]; then
        info "cross-compiling → $RUST_TARGET"
        if command -v cargo-zigbuild &>/dev/null; then
            cargo zigbuild --workspace --release --target "$RUST_TARGET" 2>&1 | tail -3
        else
            cargo build --workspace --release --target "$RUST_TARGET" 2>&1 | tail -3
        fi
    fi
    ok "build done"
else
    [ -x "$NAB_LOCAL" ] && [ -x "$NAB_COORD" ] || { err "binaries missing (rebuild or drop --no-build)"; err "  local: $NAB_LOCAL"; err "  coord: $NAB_COORD"; exit 1; }
    hdr "skip build (--no-build)"
fi

# ── deploy coord to A ───────────────────────────────────────────────────
hdr "deploy coord → $HOST_A"
sshq "$HOST_A" "systemctl stop naboscale-coord 2>/dev/null || true"
scpq "$HOST_A" "$NAB_COORD" /usr/local/bin/naboscale-coord
scpq "$HOST_A" "$SCRIPT_DIR/naboscale-coord.service" /etc/systemd/system/naboscale-coord.service

sshq "$HOST_A" bash -s << COORD
set -euo pipefail
chmod +x /usr/local/bin/naboscale-coord
mkdir -p /var/lib/naboscale
mkdir -p /etc/systemd/system/naboscale-coord.service.d
cat > /etc/systemd/system/naboscale-coord.service.d/port.conf << 'ENV'
[Service]
Environment="NABOSCALE_COORD_ADDR=0.0.0.0:${COORD_PORT}"
Environment="NABOSCALE_COORD_DB=/var/lib/naboscale/coord.sqlite"
ENV
systemctl daemon-reload
systemctl stop naboscale-coord 2>/dev/null || true
rm -f /var/lib/naboscale/coord.sqlite
systemctl start naboscale-coord
systemctl enable naboscale-coord
COORD

for i in $(seq 1 10); do
    curl -sf "$COORD_URL/v1/health" 2>/dev/null | grep -q ok && break
    [ "$i" = "10" ] && { err "coord not responding at $COORD_URL"; exit 1; }
    sleep 1
done
ok "coord ready: $COORD_URL"

# ── detect endpoints ────────────────────────────────────────────────────
hdr "detect endpoints"
A_IP=$(sshq "$HOST_A" "hostname -I 2>/dev/null | awk '{print \$1}' || ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1")
A_IP="${A_IP:-$HOST_A}"

# For the local machine, find the IP that can reach HOST_A
B_IP=""
if is_local "$HOST_B"; then
    # macOS: use the interface that routes to HOST_A
    B_IP=$(route -n get "$HOST_A" 2>/dev/null | awk '/interface:/{print $2}' | head -1 | xargs ifconfig 2>/dev/null | awk '/inet /{print $2}' | head -1)
    [ -z "$B_IP" ] && B_IP=$(ifconfig 2>/dev/null | awk '/inet / && !/127.0.0.1/{print $2; exit}')
    [ -z "$B_IP" ] && B_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$B_IP" ] && B_IP="$HOST_B"
else
    B_IP=$(sshq "$HOST_B" "hostname -I 2>/dev/null | awk '{print \$1}' || ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1")
    B_IP="${B_IP:-$HOST_B}"
fi

A_EP="${A_IP}:${MESH_PORT}"
B_EP="${B_IP}:${MESH_PORT}"
ok "A (VPN):     $A_EP  (coord: $COORD_URL)"
ok "B (Mac/alt): $B_EP"

# ── deploy CLI binary ───────────────────────────────────────────────────
hdr "deploy CLI"
copy_bin "$HOST_A" "$NAB_REMOTE" /usr/local/bin/naboscale
run_on "$HOST_A" "chmod +x /usr/local/bin/naboscale"
# If HOST_B is another remote machine, deploy the cross-compiled binary there too
if ! is_local "$HOST_B" && [ "$HOST_A" != "$HOST_B" ]; then
    copy_bin "$HOST_B" "$NAB_REMOTE" /usr/local/bin/naboscale
    run_on "$HOST_B" "chmod +x /usr/local/bin/naboscale"
fi
ok "CLI deployed"

# ── setup node 1 (A = remote, Linux) ────────────────────────────────────
hdr "setup node 1 on $HOST_A"
sshq "$HOST_A" NABOSCALE_PASSPHRASE="$PASSPHRASE" bash -s << N1
set -euo pipefail
export NABOSCALE_PASSPHRASE PATH="/usr/local/bin:\$PATH"
rm -rf "$NODE1_DIR"; mkdir -p "$NODE1_DIR"
naboscale --config-dir "$NODE1_DIR" init --server "$COORD_URL" --force
naboscale --config-dir "$NODE1_DIR" register
naboscale --config-dir "$NODE1_DIR" heartbeat --endpoint "$A_EP"
N1

N1_IP=$(sshq "$HOST_A" NABOSCALE_PASSPHRASE="$PASSPHRASE" bash -s <<< "export PATH=/usr/local/bin:\$PATH; naboscale --config-dir $NODE1_DIR status" | awk '/^ip:/{print $2}')
ok "node 1 → mesh IP: $N1_IP"

# ── setup node 2 (B = local or remote) ──────────────────────────────────
hdr "setup node 2 on $HOST_B"
export NABOSCALE_PASSPHRASE="$PASSPHRASE"
export PATH="/usr/local/bin:$PATH"

N2_NAB="$NAB_REMOTE"
if is_local "$HOST_B"; then
    N2_NAB="$NAB_LOCAL"
else
    scpq "$HOST_B" "$NAB_REMOTE" /usr/local/bin/naboscale
    sshq "$HOST_B" "chmod +x /usr/local/bin/naboscale"
    N2_NAB="naboscale"  # use deployed binary in PATH
fi

N2_SETUP=$(cat << N2
rm -rf "$NODE2_DIR"; mkdir -p "$NODE2_DIR"
$N2_NAB --config-dir "$NODE2_DIR" init --server "$COORD_URL" --force
$N2_NAB --config-dir "$NODE2_DIR" register
$N2_NAB --config-dir "$NODE2_DIR" heartbeat --endpoint "$B_EP"
N2
)

if is_local "$HOST_B"; then
    eval "$N2_SETUP"
    N2_IP=$("$NAB_LOCAL" --config-dir "$NODE2_DIR" status | awk '/^ip:/{print $2}')
else
    sshq "$HOST_B" NABOSCALE_PASSPHRASE="$PASSPHRASE" bash -s <<< "
export PATH=/usr/local/bin:\$PATH
$N2_SETUP"
    N2_IP=$(sshq "$HOST_B" NABOSCALE_PASSPHRASE="$PASSPHRASE" "export PATH=/usr/local/bin:\$PATH; naboscale --config-dir $NODE2_DIR status" | awk '/^ip:/{print $2}')
fi
ok "node 2 → mesh IP: $N2_IP"

# ── verify peers ────────────────────────────────────────────────────────
hdr "peer visibility"
P1=$(sshq "$HOST_A" NABOSCALE_PASSPHRASE="$PASSPHRASE" bash -s <<< "export PATH=/usr/local/bin:\$PATH; naboscale --config-dir $NODE1_DIR peers" | grep -c "endpoint=" || echo 0)
P2=$("$NAB_LOCAL" --config-dir "$NODE2_DIR" peers 2>/dev/null | grep -c "endpoint=" || echo 0)
info "node 1 sees $P1 peer(s), node 2 sees $P2 peer(s)"

# ── start tunnels ───────────────────────────────────────────────────────
hdr "start tunnels"

# Launch node 1 on remote host (SSH, fire-and-forget).
info "launching node 1 ($HOST_A)"
sshq "$HOST_A" NABOSCALE_PASSPHRASE="$PASSPHRASE" \
    "nohup env NABOSCALE_PASSPHRASE='$PASSPHRASE' PATH=/usr/local/bin:\$PATH \
     naboscale --config-dir '$NODE1_DIR' up \
     --tun utun99 --bind-port $MESH_PORT --advertise-endpoint '$A_EP' \
     </dev/null >/var/log/naboscale-node1.log 2>&1 & echo \$!"
# The SSH command returns the remote PID; capture it just for logging.
ok "node 1 launched"

# Launch node 2 locally.
info "launching node 2 ($HOST_B)"
if is_local "$HOST_B"; then
    if [ "$(uname -s)" = "Darwin" ]; then
        sudo -n --preserve-env=NABOSCALE_PASSPHRASE,PATH \
            nohup "$NAB_LOCAL" --config-dir "$NODE2_DIR" up \
            --tun utun99 --bind-port "$MESH_PORT" --advertise-endpoint "$B_EP" \
            </dev/null >/tmp/naboscale-node2.log 2>&1 &
    else
        nohup "$NAB_LOCAL" --config-dir "$NODE2_DIR" up \
            --tun utun99 --bind-port "$MESH_PORT" --advertise-endpoint "$B_EP" \
            </dev/null >/tmp/naboscale-node2.log 2>&1 &
    fi
else
    sshq "$HOST_B" NABOSCALE_PASSPHRASE="$PASSPHRASE" \
        "nohup env NABOSCALE_PASSPHRASE='$PASSPHRASE' PATH=/usr/local/bin:\$PATH \
         naboscale --config-dir '$NODE2_DIR' up \
         --tun utun99 --bind-port $MESH_PORT --advertise-endpoint '$B_EP' \
         </dev/null >/var/log/naboscale-node2.log 2>&1 & echo \$!"
fi
ok "node 2 launched"
sleep 2

# ── wait for TUN + handshake ─────────────────────────────────────────────
hdr "establishing mesh"
TUN1_OK=0; TUN2_OK=0; HS1_OK=0; HS2_OK=0
HS_TIMEOUT=30
info "waiting for TUN devices and handshake (timeout ${HS_TIMEOUT}s)"

for i in $(seq 1 $HS_TIMEOUT); do
    # Check TUN on node 1
    if [ "$TUN1_OK" = "0" ] && sshq "$HOST_A" "ip link show utun99 >/dev/null 2>&1" 2>/dev/null; then
        TUN1_OK=1; ok "node 1 TUN up"
    fi
    # Check TUN on node 2
    if [ "$TUN2_OK" = "0" ]; then
        if is_local "$HOST_B"; then
            ifconfig utun99 >/dev/null 2>&1 && { TUN2_OK=1; ok "node 2 TUN up"; }
        else
            sshq "$HOST_B" "ip link show utun99 >/dev/null 2>&1" 2>/dev/null && { TUN2_OK=1; ok "node 2 TUN up"; }
        fi
    fi
    # Check handshake on node 1 (grep log for "handshake.*complete")
    if [ "$HS1_OK" = "0" ]; then
        sshq "$HOST_A" "grep -q 'handshake.*complete' /var/log/naboscale-node1.log 2>/dev/null" 2>/dev/null && { HS1_OK=1; ok "node 1 handshake complete"; }
    fi
    # Check handshake on node 2
    if [ "$HS2_OK" = "0" ]; then
        grep -q 'handshake.*complete' /tmp/naboscale-node2.log 2>/dev/null && { HS2_OK=1; ok "node 2 handshake complete"; }
    fi
    # All good?
    if [ "$TUN1_OK" = "1" ] && [ "$TUN2_OK" = "1" ]; then
        if [ "$HS1_OK" = "1" ] && [ "$HS2_OK" = "1" ]; then
            ok "mesh ready in ${i}s"
            break
        fi
    fi
    printf "."; sleep 1
done
echo
[ "$TUN1_OK" = "0" ] && warn "node 1 TUN did not come up"
[ "$TUN2_OK" = "0" ] && warn "node 2 TUN did not come up"
if [ "$HS1_OK" = "0" ] || [ "$HS2_OK" = "0" ]; then
    warn "handshake incomplete after ${HS_TIMEOUT}s — pings may fail"
fi

hdr "ping test"
PASS=0

info "A→B ($N1_IP → $N2_IP)"
if sshq "$HOST_A" "ping -c 3 -W 2 -I $N1_IP $N2_IP" 2>&1 | grep -q "0% packet loss"; then
    ok "A→B OK"
    PASS=$((PASS + 1))
else
    err "A→B FAIL"
    sshq "$HOST_A" "ping -c 1 -W 2 -I $N1_IP $N2_IP" 2>&1 | tail -3 | sed 's/^/      /'
fi

info "B→A ($N2_IP → $N1_IP)"
PING_B=$(if is_local "$HOST_B"; then ping -c 3 -W 2 -I "$N2_IP" "$N1_IP" 2>&1; else sshq "$HOST_B" "ping -c 3 -W 2 -I $N2_IP $N1_IP" 2>&1; fi)
if echo "$PING_B" | grep -q "0% packet loss"; then
    ok "B→A OK"
    PASS=$((PASS + 1))
else
    err "B→A FAIL"
    echo "$PING_B" | tail -3 | sed 's/^/      /'
fi

# ── logs ────────────────────────────────────────────────────────────────
hdr "recent logs"
echo "── node 1 ($HOST_A) ──"
sshq "$HOST_A" "tail -12 /var/log/naboscale-node1.log 2>/dev/null" | sed 's/^/  /' || echo "  (none)"

echo "── node 2 ($HOST_B) ──"
if is_local "$HOST_B"; then
    tail -12 /tmp/naboscale-node2.log 2>/dev/null | sed 's/^/  /' || echo "  (none)"
else
    sshq "$HOST_B" "tail -12 /var/log/naboscale-node2.log 2>/dev/null" | sed 's/^/  /' || echo "  (none)"
fi

# ── summary ─────────────────────────────────────────────────────────────
hdr "result"
printf "  coord:      %s\n" "$COORD_URL"
printf "  node 1 (A): %-15s  mesh=%-15s  endpoint=%s\n" "$HOST_A" "$N1_IP" "$A_EP"
printf "  node 2 (B): %-15s  mesh=%-15s  endpoint=%s\n" "$HOST_B" "$N2_IP" "$B_EP"
printf "  passphrase: %s\n" "$PASSPHRASE"
printf "  pings:      %d/2 passed\n" "$PASS"
echo

if [ "$KEEP" = "1" ]; then
    info "nodes kept alive (--keep)"
    echo "  stop A: ssh $HOST_A 'pkill -f node1'"
    [ is_local "$HOST_B" ] && echo "  stop B: pkill -f node2" || echo "  stop B: ssh $HOST_B 'pkill -f node2'"
    echo "  logs A: ssh $HOST_A 'tail -f /var/log/naboscale-node1.log'"
    echo "  ping:  ssh $HOST_A 'ping -I $N1_IP $N2_IP'"
    while true; do sleep 60; done
fi

[ "$PASS" = "2" ] && { ok "ALL PINGS PASSED — mesh VPN working ✓"; exit 0; }
err "PINGS FAILED — check logs above"
exit 1
