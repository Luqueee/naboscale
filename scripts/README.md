# Test scripts

These scripts run on the **vpn** machine (where the coord server, TUN devices, and root live) — not on a developer laptop. They are kept in git so the test workflow is versioned alongside the code.

## Files

- **`test-mesh.sh`** — two-node mesh smoke test. Creates nodes `A` (100.100.0.1) and `B` (100.100.0.2), runs `naboscale up` on both, pings both directions through the TUNs. Fast (~10 s).
- **`test-all.sh`** — comprehensive 6-section suite (15 tests): build, coord health, CLI workflow, security (bad sig / no token / bad token), persistence, mesh ping. Slow (~2-3 min).

## Layout on the vpn

```
/root/naboscale/
├── crates/                # source
├── target/release/        # built binaries (naboscale, naboscale-coord)
└── scripts/
    ├── test-mesh.sh       # ← you are here
    └── test-all.sh
```

## Running on the vpn

```bash
ssh vpn
cd /root/naboscale
export PATH="$HOME/.cargo/bin:$PATH"   # rustup cargo, not apt's

# Mesh only
./scripts/test-mesh.sh

# Full suite
./scripts/test-all.sh
```

Exit code `0` = all pass, non-zero = at least one failed. The full suite prints a per-section report and a final summary line.

## Syncing the local copy

The canonical source of these scripts is on the vpn. To refresh the local copy after editing on the vpn:

```bash
scp vpn:/root/naboscale/scripts/test-*.sh /Users/adria/Documents/programacion/projects/naboscale/scripts/
```

## Editing

Prefer editing on the vpn first, running the suite, then pulling the change to local and committing. Keep both copies identical.
