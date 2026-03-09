# Guide

This guide covers the hard-cut V2 shell workflows now owned by `igloo-shell`.

## Prerequisites

- Rust toolchain installed (`cargo`, `rustfmt`, `clippy`)

## 1. Build Baseline

```bash
cargo check --workspace
cargo test --workspace
```

## 2. Inspect the Shell Store

The hard-cut shell uses XDG-backed config, data, and state directories for relay profiles and managed profiles.

```bash
cargo run -p igloo-shell-cli -- relays list
cargo run -p igloo-shell-cli -- profile list
```

The full target UX is specified in `V2-SHELL-SPEC.md`. The current implementation includes managed profiles, daemon/runtime commands, invite flows, the daemon-backed TUI, and managed-profile release scripts.

## 3. Generate Local Artifacts

```bash
cargo run -p igloo-shell-cli -- dev keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
```

Generated files include:
- `./data/group.json`
- `./data/share-<name>.json`
- `./data/igloo-shell-<name>.json`

The generated `igloo-shell-<name>.json` files are developer artifacts for lower-level runtime hosting. Normal operator flows should import the group/share material into managed shell profiles.

## 4. Start Relay

```bash
cargo run -p igloo-shell-cli -- dev relay --host 127.0.0.1 --port 8194
```

## 5. Shell-Owned Dev E2E

```bash
cargo run -p igloo-shell-cli --offline -- dev e2e-node --out-dir ./data --relay ws://127.0.0.1:8194
cargo run -p igloo-shell-cli --offline -- dev e2e-full --threshold 11 --count 15
```

Wrapper scripts are also available:

```bash
scripts/devnet.sh gen
scripts/devnet.sh start
scripts/devnet.sh status
scripts/devnet.sh smoke
scripts/devnet-tmux.sh start
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

## 6. Launch The Daemon-Backed TUI

```bash
cargo run -p igloo-shell-cli -- daemon start --profile <profile-id>
cargo run -p igloo-shell-cli -- tui --profile <profile-id>
```

The TUI attaches to the per-profile daemon. It does not boot a separate runtime from raw config files.

## Next Reading

- `V2-SHELL-SPEC.md`
- `OPERATIONS.md`
- `CONFIGURATION.md`
- `TESTING.md`
- `../../../docs/FROSTR-ARCHITECTURE.md`
