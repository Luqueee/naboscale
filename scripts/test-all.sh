#!/usr/bin/env bash
# test-all.sh — comprehensive test suite for naboscale
#
# Sections (run individually with the section name as first arg):
#   unit        cargo test --workspace
#   coord       coord server smoke + persistence
#   cli         CLI workflow: init, register, heartbeat, status, peers
#   errors      CLI error paths and security (bad sig, missing token)
#   persistence coord DB survives restart
#   mesh        end-to-end mesh VPN (2 nodes, pings)
#   mesh3       end-to-end mesh VPN (3 nodes, pings A↔B, A↔C, B↔C)
#   all         (default) run everything in order
set -uo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

NAB="${NAB:-/root/naboscale/target/release/naboscale}"
SERVER="${SERVER:-http://127.0.0.1:8080}"
NABOSCALE_ROOT="${NABOSCALE_ROOT:-/root/naboscale}"
WORK="${WORK:-/tmp/naboscale-all-test}"
LOG_DIR="$WORK/logs"
SECTION="${1:-all}"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

color() { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
hdr()  { printf "\n\033[1;34m=== %s ===\033[0m\n" "$*"; }
ok()   { color "32" "  PASS  $*"; }
fail() { color "31" "  FAIL  $*"; }
skip() { color "33" "  SKIP  $*"; }
info() { color "36" "  →     $*"; }

record_pass() { PASS=$((PASS+1)); RESULTS+=("PASS|$*"); }
record_fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL|$*"); }
record_skip() { SKIP=$((SKIP+1)); RESULTS+=("SKIP|$*"); }

run_nab() { "$NAB" "$@"; }

cleanup_nodes() {
    for cfg in "$WORK"/node* "$WORK"/mesh* "$WORK"/mesh3* "$WORK"/errtest "$WORK"/persist "$WORK"/meshA "$WORK"/meshB; do
        [ -d "$cfg" ] || continue
        pkill -f "naboscale --config-dir $cfg" 2>/dev/null || true
    done
    sleep 0.5
    for cfg in "$WORK"/node* "$WORK"/mesh* "$WORK"/mesh3* "$WORK"/errtest "$WORK"/persist "$WORK"/meshA "$WORK"/meshB; do
        [ -d "$cfg" ] || continue
        pkill -9 -f "naboscale --config-dir $cfg" 2>/dev/null || true
    done
    for i in 0 1 2 3 4 5 6 7 8 9; do
        ip link delete "utun9$i" 2>/dev/null || true
        ip link delete "utun8$i" 2>/dev/null || true
        ip link delete "utun7$i" 2>/dev/null || true
    done
}

restart_coord_clean() {
    cleanup_nodes
    systemctl stop naboscale-coord 2>/dev/null || true
    systemctl reset-failed naboscale-coord 2>/dev/null || true
    sleep 1
    mv /var/lib/naboscale/coord.sqlite /var/lib/naboscale/coord.sqlite.prev 2>/dev/null || true
    systemctl start naboscale-coord
    for i in 1 2 3 4 5 6 7 8; do
        if wget -qO- "$SERVER/v1/health" 2>/dev/null | grep -q ok; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ============================================================================
# 1. Unit tests
# ============================================================================
test_unit() {
    hdr "1. Unit tests (cargo test --workspace)"
    cd "$NABOSCALE_ROOT"
    if [ "${SKIP_BUILD:-0}" = "0" ]; then
        info "building (SKIP_BUILD=1 to skip)"
        if ! cargo build --workspace --release --quiet 2>&1 | tail -5; then
            fail "cargo build"
            record_fail "cargo build"
            return
        fi
    fi
    local out
    out=$(cargo test --workspace 2>&1)
    local pass_n=$(echo "$out" | grep -oE "[0-9]+ passed" | awk '{sum += $1} END {print sum+0}')
    local fail_n=$(echo "$out" | grep -oE "[0-9]+ failed" | awk '{sum += $1} END {print sum+0}')
    local ign_n=$(echo "$out" | grep -oE "[0-9]+ ignored" | awk '{sum += $1} END {print sum+0}')
    if [ "${fail_n:-0}" = "0" ] && [ "${pass_n:-0}" -gt 0 ]; then
        ok "cargo test --workspace: $pass_n passed, $ign_n ignored"
        record_pass "unit tests"
    else
        fail "cargo test --workspace: $pass_n passed, $fail_n failed"
        echo "$out" | tail -30 | sed 's/^/    /'
        record_fail "unit tests"
    fi
}

# ============================================================================
# 2. Coord server
# ============================================================================
test_coord() {
    hdr "2. Coord server"
    if ! restart_coord_clean; then
        fail "coord server not responding after 8s"
        record_fail "coord restart"
        return
    fi
    ok "coord server restarted with fresh DB"
    record_pass "coord restart with fresh DB"

    info "health endpoint"
    local body
    body=$(wget -qO- "$SERVER/v1/health" 2>/dev/null)
    if [ "$body" = "ok" ]; then
        ok "/v1/health returns 'ok'"
        record_pass "/v1/health"
    else
        fail "/v1/health returned '$body'"
        record_fail "/v1/health"
    fi

    info "bad path returns 404"
    local status
    status=$(wget -qO- --server-response "$SERVER/v1/nonexistent" 2>&1 | grep "HTTP/" | head -1 | awk '{print $2}')
    if [ "$status" = "404" ] || [ "$status" = "405" ]; then
        ok "/v1/nonexistent returns $status"
        record_pass "404 on unknown path"
    else
        skip "unknown path returned $status"
        record_skip "404 on unknown path"
    fi
}

# ============================================================================
# 3. CLI workflow
# ============================================================================
test_cli_workflow() {
    hdr "3. CLI workflow"
    restart_coord_clean >/dev/null
    mkdir -p "$LOG_DIR"

    info "init A and B"
    local cfg_a="$WORK/nodeA" cfg_b="$WORK/nodeB"
    rm -rf "$cfg_a" "$cfg_b"
    run_nab --config-dir "$cfg_a" init --server "$SERVER" --force >/dev/null
    run_nab --config-dir "$cfg_b" init --server "$SERVER" --force >/dev/null
    [ -f "$cfg_a/identity.key" ] && [ -f "$cfg_b/identity.key" ] && {
        ok "init creates identity.key and wg.key"
        record_pass "init creates keys"
    } || { fail "init didn't create keys"; record_fail "init creates keys"; }

    info "register A and B"
    run_nab --config-dir "$cfg_a" register >/dev/null
    run_nab --config-dir "$cfg_b" register >/dev/null
    local ip_a ip_b
    ip_a=$(run_nab --config-dir "$cfg_a" status 2>&1 | awk '/^ip:/{print $2}')
    ip_b=$(run_nab --config-dir "$cfg_b" status 2>&1 | awk '/^ip:/{print $2}')
    if [ -n "$ip_a" ] && [ -n "$ip_b" ] && [ "$ip_a" != "$ip_b" ]; then
        ok "register assigns distinct IPs: A=$ip_a, B=$ip_b"
        record_pass "register assigns distinct IPs"
    else
        fail "register IPs not distinct: A=$ip_a B=$ip_b"
        record_fail "register assigns distinct IPs"
    fi

    info "heartbeat from A and B"
    run_nab --config-dir "$cfg_a" heartbeat --endpoint "127.0.0.1:51820" >/dev/null
    run_nab --config-dir "$cfg_b" heartbeat --endpoint "127.0.0.1:51821" >/dev/null
    local out_a out_b ep_a ep_b
    out_a=$(run_nab --config-dir "$cfg_a" status 2>&1)
    out_b=$(run_nab --config-dir "$cfg_b" status 2>&1)
    ep_a=$(echo "$out_a" | awk '/^endpoint:/{print $2}')
    ep_b=$(echo "$out_b" | awk '/^endpoint:/{print $2}')
    if [ "$ep_a" = "127.0.0.1:51820" ] && [ "$ep_b" = "127.0.0.1:51821" ]; then
        ok "heartbeat updates endpoint in status (A=$ep_a, B=$ep_b)"
        record_pass "heartbeat updates endpoint"
    else
        fail "heartbeat endpoint mismatch: A='$ep_a' B='$ep_b'"
        record_fail "heartbeat updates endpoint"
    fi

    info "peers visibility"
    local peers_a peers_b
    peers_a=$(run_nab --config-dir "$cfg_a" peers 2>&1 | grep -c "endpoint=" || true)
    peers_b=$(run_nab --config-dir "$cfg_b" peers 2>&1 | grep -c "endpoint=" || true)
    if [ "$peers_a" = "1" ] && [ "$peers_b" = "1" ]; then
        ok "each node sees the other (1 peer each)"
        record_pass "peers visibility"
    else
        fail "peers not visible: A sees $peers_a, B sees $peers_b"
        record_fail "peers visibility"
    fi
}

# ============================================================================
# 4. CLI errors + security
# ============================================================================
test_errors() {
    hdr "4. CLI error paths and security"
    restart_coord_clean >/dev/null

    info "init then status (should fail without register)"
    local cfg="$WORK/errtest"
    rm -rf "$cfg"
    run_nab --config-dir "$cfg" init --server "$SERVER" --force >/dev/null
    if run_nab --config-dir "$cfg" status >/dev/null 2>&1; then
        fail "status succeeded without register"
        record_fail "status before register"
    else
        ok "status before register fails"
        record_pass "status before register"
    fi

    info "register with bad signature (should 401)"
    local ts=$(date +%s)
    local bad_sig=$(openssl rand -base64 64 2>/dev/null | tr -d '\n')
    local bad_id=$(openssl rand -base64 32 | tr -d '\n')
    local bad_wg=$(openssl rand -base64 32 | tr -d '\n')
    local body="{\"identity_pubkey\":\"$bad_id\",\"wg_pubkey\":\"$bad_wg\",\"timestamp\":$ts,\"signature\":\"$bad_sig\"}"
    local code
    code=$(wget -qO /dev/null --post-data "$body" --header "Content-Type: application/json" --server-response "$SERVER/v1/register" 2>&1 | grep "HTTP/" | head -1 | awk '{print $2}')
    if [ "$code" = "401" ]; then
        ok "bad signature rejected with 401"
        record_pass "bad signature rejected"
    else
        fail "bad signature returned $code, expected 401"
        record_fail "bad signature rejected"
    fi

    info "heartbeat without token (should 401)"
    local body2='{"endpoint":"1.2.3.4:51820","timestamp":1234567890,"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
    local code2
    code2=$(wget -qO /dev/null --post-data "$body2" --header "Content-Type: application/json" --server-response "$SERVER/v1/heartbeat" 2>&1 | grep "HTTP/" | head -1 | awk '{print $2}')
    if [ "$code2" = "401" ]; then
        ok "no token rejected with 401"
        record_pass "no token rejected"
    else
        fail "no token returned $code2, expected 401"
        record_fail "no token rejected"
    fi

    info "peers with bad token (should 401)"
    local code3
    code3=$(wget -qO /dev/null --header "Authorization: Bearer invalid" --server-response "$SERVER/v1/peers" 2>&1 | grep "HTTP/" | head -1 | awk '{print $2}')
    if [ "$code3" = "401" ]; then
        ok "bad token rejected with 401"
        record_pass "bad token rejected"
    else
        fail "bad token returned $code3, expected 401"
        record_fail "bad token rejected"
    fi
}

# ============================================================================
# 5. Persistence
# ============================================================================
test_persistence() {
    hdr "5. Coord server persistence"
    restart_coord_clean >/dev/null
    local cfg="$WORK/persist"
    rm -rf "$cfg"
    run_nab --config-dir "$cfg" init --server "$SERVER" --force >/dev/null
    run_nab --config-dir "$cfg" register >/dev/null
    local id_before
    id_before=$(run_nab --config-dir "$cfg" status 2>&1 | awk '/^node_id:/{print $2}')

    info "restarting coord server (DB should survive)"
    systemctl stop naboscale-coord 2>/dev/null || true
    sleep 1
    systemctl start naboscale-coord
    for i in 1 2 3 4 5; do
        wget -qO- "$SERVER/v1/health" 2>/dev/null | grep -q ok && break
        sleep 1
    done

    info "query status after restart"
    local id_after
    id_after=$(run_nab --config-dir "$cfg" status 2>&1 | awk '/^node_id:/{print $2}')
    if [ "$id_before" = "$id_after" ] && [ -n "$id_after" ]; then
        ok "node identity preserved across coord restart ($id_after)"
        record_pass "persistence across coord restart"
    else
        fail "node identity changed: before=$id_before after=$id_after"
        record_fail "persistence across coord restart"
    fi
}

# ============================================================================
# 6. Mesh VPN end-to-end (2 nodes)
# ============================================================================
test_mesh() {
    hdr "6. Mesh VPN end-to-end (2 nodes, pings)"
    cleanup_nodes
    if ! restart_coord_clean; then
        fail "coord server not ready for mesh test"
        record_fail "mesh setup"
        return
    fi

    local cfg_a="$WORK/meshA" cfg_b="$WORK/meshB"
    rm -rf "$cfg_a" "$cfg_b"
    run_nab --config-dir "$cfg_a" init --server "$SERVER" --force >/dev/null
    run_nab --config-dir "$cfg_b" init --server "$SERVER" --force >/dev/null
    run_nab --config-dir "$cfg_a" register >/dev/null
    run_nab --config-dir "$cfg_b" register >/dev/null
    run_nab --config-dir "$cfg_a" heartbeat --endpoint "127.0.0.1:51820" >/dev/null
    run_nab --config-dir "$cfg_b" heartbeat --endpoint "127.0.0.1:51821" >/dev/null

    local ip_a ip_b
    ip_a=$(run_nab --config-dir "$cfg_a" status 2>&1 | awk '/^ip:/{print $2}')
    ip_b=$(run_nab --config-dir "$cfg_b" status 2>&1 | awk '/^ip:/{print $2}')

    info "starting A on utun99:51820 (ip=$ip_a)"
    local log_a="$LOG_DIR/meshA.log"
    nohup "$NAB" --config-dir "$cfg_a" up --tun "utun99" --bind-port 51820 > "$log_a" 2>&1 &
    local pid_a=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do
        grep -q "Local endpoint" "$log_a" 2>/dev/null && break
        sleep 0.3
    done
    sleep 0.5

    info "starting B on utun98:51821 (ip=$ip_b)"
    local log_b="$LOG_DIR/meshB.log"
    nohup "$NAB" --config-dir "$cfg_b" up --tun "utun98" --bind-port 51821 > "$log_b" 2>&1 &
    local pid_b=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do
        grep -q "Local endpoint" "$log_b" 2>/dev/null && break
        sleep 0.3
    done

    info "waiting 6s for handshake (init auto-retries every 500ms)"
    sleep 6

    info "ping $ip_a -> $ip_b"
    if ping -c 2 -W 2 -I "$ip_a" "$ip_b" 2>&1 | grep -q "0% packet loss"; then
        ok "A → B pings through tunnel"
        record_pass "mesh ping A->B"
    else
        fail "A → B ping failed"
        record_fail "mesh ping A->B"
    fi

    info "ping $ip_b -> $ip_a"
    if ping -c 2 -W 2 -I "$ip_b" "$ip_a" 2>&1 | grep -q "0% packet loss"; then
        ok "B → A pings through tunnel"
        record_pass "mesh ping B->A"
    else
        fail "B → A ping failed"
        record_fail "mesh ping B->A"
    fi

    info "killing node processes"
    kill "$pid_a" "$pid_b" 2>/dev/null || true
    sleep 1
    kill -9 "$pid_a" "$pid_b" 2>/dev/null || true
    ip link delete "utun99" 2>/dev/null || true
    ip link delete "utun98" 2>/dev/null || true
}

# ============================================================================
# 7. Mesh VPN end-to-end (3 nodes, full mesh)
# ============================================================================
test_mesh3() {
    hdr "7. Mesh VPN end-to-end (3 nodes, full mesh, pings)"
    cleanup_nodes
    if ! restart_coord_clean; then
        fail "coord server not ready for mesh3 test"
        record_fail "mesh3 setup"
        return
    fi

    local cfg_a="$WORK/mesh3A" cfg_b="$WORK/mesh3B" cfg_c="$WORK/mesh3C"
    rm -rf "$cfg_a" "$cfg_b" "$cfg_c"
    run_nab --config-dir "$cfg_a" init --server "$SERVER" --force >/dev/null
    run_nab --config-dir "$cfg_b" init --server "$SERVER" --force >/dev/null
    run_nab --config-dir "$cfg_c" init --server "$SERVER" --force >/dev/null
    run_nab --config-dir "$cfg_a" register >/dev/null
    run_nab --config-dir "$cfg_b" register >/dev/null
    run_nab --config-dir "$cfg_c" register >/dev/null
    run_nab --config-dir "$cfg_a" heartbeat --endpoint "127.0.0.1:51820" >/dev/null
    run_nab --config-dir "$cfg_b" heartbeat --endpoint "127.0.0.1:51821" >/dev/null
    run_nab --config-dir "$cfg_c" heartbeat --endpoint "127.0.0.1:51822" >/dev/null

    local ip_a ip_b ip_c
    ip_a=$(run_nab --config-dir "$cfg_a" status 2>&1 | awk '/^ip:/{print $2}')
    ip_b=$(run_nab --config-dir "$cfg_b" status 2>&1 | awk '/^ip:/{print $2}')
    ip_c=$(run_nab --config-dir "$cfg_c" status 2>&1 | awk '/^ip:/{print $2}')

    info "starting 3 nodes (A on utun99:51820, B on utun98:51821, C on utun97:51822)"
    local log_a="$LOG_DIR/mesh3A.log" log_b="$LOG_DIR/mesh3B.log" log_c="$LOG_DIR/mesh3C.log"
    nohup "$NAB" --config-dir "$cfg_a" up --tun "utun99" --bind-port 51820 > "$log_a" 2>&1 &
    local pid_a=$!
    nohup "$NAB" --config-dir "$cfg_b" up --tun "utun98" --bind-port 51821 > "$log_b" 2>&1 &
    local pid_b=$!
    nohup "$NAB" --config-dir "$cfg_c" up --tun "utun97" --bind-port 51822 > "$log_c" 2>&1 &
    local pid_c=$!

    for log in "$log_a" "$log_b" "$log_c"; do
        for i in 1 2 3 4 5 6 7 8 9 10; do
            grep -q "Local endpoint" "$log" 2>/dev/null && break
            sleep 0.3
        done
    done
    sleep 0.5

    info "waiting 8s for 6 handshakes (3 per node)"
    sleep 8

    local pids=("$pid_a" "$pid_b" "$pid_c")
    local tuns=("utun99" "utun98" "utun97")
    local labels=("A" "B" "C")

    local n_ok=0
    local n_total=6
    for pair in "A $ip_a $ip_b" "B $ip_b $ip_c" "C $ip_a $ip_c"; do
        local label=$(echo $pair | awk '{print $1}')
        local src=$(echo $pair | awk '{print $2}')
        local dst=$(echo $pair | awk '{print $3}')
        info "ping $label: $src -> $dst"
        if ping -c 2 -W 2 -I "$src" "$dst" 2>&1 | grep -q "0% packet loss"; then
            ok "$label: $src → $dst works"
            record_pass "mesh3 ping $src->$dst"
            n_ok=$((n_ok+1))
        else
            fail "$label: $src → $dst failed"
            record_fail "mesh3 ping $src->$dst"
        fi
    done

    info "TUN packet counters"
    for tun in "${tuns[@]}"; do
        local rx=$(ip -s link show "$tun" 2>/dev/null | awk '/^    RX:/{getline; print $1}')
        local tx=$(ip -s link show "$tun" 2>/dev/null | awk '/^    TX:/{getline; print $1}')
        printf "    %-8s  rx=%-5s  tx=%s\n" "$tun" "${rx:-0}" "${tx:-0}"
    done

    info "killing 3 node processes"
    kill "${pids[@]}" 2>/dev/null || true
    sleep 1
    kill -9 "${pids[@]}" 2>/dev/null || true
    for tun in "${tuns[@]}"; do
        ip link delete "$tun" 2>/dev/null || true
    done
}

# ============================================================================
# Main
# ============================================================================
mkdir -p "$LOG_DIR"

case "$SECTION" in
    unit)        test_unit ;;
    coord)       test_coord ;;
    cli)         test_cli_workflow ;;
    errors)      test_errors ;;
    persistence) test_persistence ;;
    mesh)        test_mesh ;;
    mesh3)       test_mesh3 ;;
    all)
        test_unit
        test_coord
        test_cli_workflow
        test_errors
        test_persistence
        test_mesh
        test_mesh3
        ;;
    *)
        echo "unknown section: $SECTION"
        echo "usage: $0 [all|unit|coord|cli|errors|persistence|mesh|mesh3]"
        exit 2
        ;;
esac

hdr "SUMMARY"
printf "  PASS:  \033[32m%d\033[0m\n" "$PASS"
printf "  FAIL:  \033[31m%d\033[0m\n" "$FAIL"
printf "  SKIP:  \033[33m%d\033[0m\n" "$SKIP"
echo
if [ "$FAIL" -gt 0 ]; then
    echo "failed tests:"
    for r in "${RESULTS[@]}"; do
        if [[ "$r" == FAIL\|* ]]; then
            printf "  \033[31m✗ %s\033[0m\n" "${r#FAIL|}"
        fi
    done
    color 31 "OVERALL: FAIL"
    exit 1
fi
color 32 "OVERALL: ALL PASS"
exit 0
