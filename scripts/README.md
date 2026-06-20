# Scripts

Everything lives here: tests, deploy, systemd units.

## Quick start — deploy to two machines

```bash
# 1. Tell the script which machines to use
echo 'HOST_A=10.0.0.1'  > scripts/.deploy.conf
echo 'HOST_B=10.0.0.2' >> scripts/.deploy.conf

# 2. Run it
./scripts/deploy-mesh.sh

# Done. Pings A ↔ B through the mesh tunnel.
```

No flags needed. Reads `scripts/.deploy.conf` (or env vars `DEPLOY_A` / `DEPLOY_B`). See `scripts/.deploy.conf.example`.

Overrides (all optional):
```bash
./scripts/deploy-mesh.sh --a 10.0.0.1 --b 10.0.0.2   # explicit hosts
./scripts/deploy-mesh.sh --no-build                     # skip cargo build
./scripts/deploy-mesh.sh --keep                         # leave nodes running
```

Prerequisites on both machines: Linux, systemd, SSH key access, ports 8080/tcp + 51820/udp open.

---

## Files

| File | Purpose |
|------|---------|
| `deploy-mesh.sh`           | Zero-config 2-machine deploy + ping test |
| `.deploy.conf.example`     | Config template for deploy-mesh.sh |
| `naboscale-coord.service`  | systemd unit for the coord server |
| `test-mesh.sh`             | Local N-node mesh smoke test |
| `test-all.sh`              | Full 7-section suite (unit, coord, CLI, errors, persistence, mesh2, mesh3) |

## Local tests (single machine)

```bash
# 2-node mesh (~10 s)
./scripts/test-mesh.sh

# Full suite (unit tests + integration + mesh pings, ~2-3 min)
./scripts/test-all.sh
```

Environment overrides:
- `NAB` — path to naboscale binary (default: `target/release/naboscale`)
- `SERVER` — coord URL (default: `http://127.0.0.1:8080`)
- `SKIP_BUILD=1` — skip cargo build in test-all
