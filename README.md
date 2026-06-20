# naboscale

WireGuard-style mesh VPN with a coordination server. Supports peers behind NAT
via a transparent relay path.

## Workspace layout

| crate                  | role                                                |
|------------------------|-----------------------------------------------------|
| `naboscale-crypto`     | Noise IKpsk2 handshake + transport keys             |
| `naboscale-proto`      | wire formats                                        |
| `naboscale-tunnel`     | TUN device + per-peer session manager (UDP)         |
| `naboscale-coord`      | HTTP coordination server (`/v1/register|peers|heartbeat`) |
| `naboscale-cli`        | `naboscale` binary (`init`, `register`, `up`, ...)  |

## Build

```sh
cargo build --release -p naboscale-cli -p naboscale-coord
```

Cross-compile for a Linux server from macOS (requires `cargo-zigbuild` + `zig`):

```sh
rustup target add aarch64-unknown-linux-gnu
cargo zigbuild --release -p naboscale-cli --target aarch64-unknown-linux-gnu
```

## Bring up the mesh

The mesh requires one coord server plus N node clients. Each node registers
with the coord, polls the peer list, then opens a UDP tunnel and starts
WireGuard-style handshakes.

### 1. Coord server

Run on a host the clients can reach over HTTP:

```sh
./target/release/naboscale-coord
```

Defaults to `0.0.0.0:8080` and a SQLite DB at `./naboscale-coord.sqlite`
(override with `NABOSCALE_COORD_ADDR` / `NABOSCALE_COORD_DB`). Health check:
`GET /v1/health`.

### 2. Node client

Per node, in its own config dir:

```sh
NAB=./target/release/naboscale
DIR=$HOME/.config/naboscale

$NAB --config-dir $DIR init --server http://coord.example:8080
$NAB --config-dir $DIR register
sudo RUST_LOG=info $NAB --config-dir $DIR up \
    --tun utun99 --bind-port 51820 \
    --advertise-endpoint <public-ip>:51820
```

`init` writes the identity + WG key. `register` exchanges them for a node id
and a mesh IP (100.100.0.0/16). `up` opens the TUN, sends a heartbeat with the
advertised endpoint, and runs the handshake loop until Ctrl+C.

`--advertise-endpoint` is **required** when the node binds to `0.0.0.0` or
sits behind NAT — coord stores this value as `last_endpoint` and peers use it
to reach you. Without it peers see `0.0.0.0:port` and skip you.

The keystore is encrypted with Argon2id + XChaCha20-Poly1305. Pass the
passphrase via `--passphrase-file <path>` or the `NABOSCALE_PASSPHRASE`
environment variable. On first run, `init` prompts for one interactively.

### 3. NAT'd node (with relay)

A node that cannot accept inbound UDP (home laptop behind NAT) uses
`--relay <ip:port>` pointing at any reachable peer that *can*. All outbound
packets get wrapped in `MESSAGE_TYPE_RELAY` and sent to that address; the
relay forwards by mesh-IP based on the RELAY header.

```sh
sudo RUST_LOG=info $NAB --config-dir $DIR up \
    --tun utun99 --bind-port 51820 \
    --relay 149.74.42.52:51820 \
    --advertise-endpoint 149.74.42.52:51820
```

When `--relay` is set:
- The node forces itself to **initiator** for every peer (it can reach the
  relay but peers cannot reach it).
- Peers that read this node's `via_relay` from coord force themselves to
  **responder** (they wait for the NAT'd node to initiate).
- The relay learns the NAT'd node's external `host:port` from the first
  packet and uses that learned address to forward responses back.

### 4. Local 3-node test

`scripts/test-mesh.sh` brings up N tunnels on the same machine, registers
them, pings every pair, and reports. Requires Linux (uses `ip link`).

```sh
sudo ./scripts/test-mesh.sh 3 51820 99 127.0.0.1 3
#   ^count ^base-port ^tun-base ^endpoint-host ^stagger-secs
```

## Logging

The CLI uses `tracing` with `RUST_LOG`. Default filter is `info`. The tunnel
manager emits one `INFO` line per:
- `sending handshake INIT`
- `RELAY'd INIT processed; sending RELAY-wrapped RESPONSE back via source`
- `handshake (initiator|responder) complete -> Ready`
- `learning new endpoint from RELAY source`
- `forwarding RELAY pkt`
- `identified INIT initiator via mac1; learning endpoint`

Bump to `debug` for noisy packet-level traces:

```sh
RUST_LOG=naboscale_tunnel=debug,info naboscale up ...
```

## Caveats

- The coord stores one `last_endpoint` per node — if a host has different
  reachable addresses for inside-mesh vs external peers (e.g. LAN IP for
  same-subnet peers, public IP for outside), pick the one peers actually
  need and advertise that. NAT hairpinning (reaching a NAT'd peer from
  inside the same NAT) is not assumed.
- The Noise replay window is 120 s. The handshake retry interval is 2 s;
  the responder refreshes its `current_time` to `Tai64N::now()` on each
  consume and rebuilds itself if the init is stale, so a slow first packet
  does not wedge the session.
- TUN setup needs root on macOS and Linux.
- Empty transport packets (keepalives) are consumed without writing to the
  TUN device — writing zero-length IP packets returns `EINVAL` on Linux.
