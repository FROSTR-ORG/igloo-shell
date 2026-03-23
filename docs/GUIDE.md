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

The full target UX is specified in `V2-SHELL-SPEC.md`. The current implementation includes managed profiles, daemon/runtime commands, package flows, and managed-profile release scripts.

## 3. Generate Local Artifacts

```bash
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools -- keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
```

Generated files include:
- `./data/group.json`
- `./data/share-<name>.json`
- `./data/igloo-shell-<name>.json`

The generated `igloo-shell-<name>.json` files are developer artifacts for lower-level runtime hosting. Normal operator flows should import the group/share material into managed shell profiles.

## 4. Start Relay

```bash
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools -- relay --host 127.0.0.1 --port 8194
```

## 5. Shell-Owned Dev E2E

```bash
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools --offline -- e2e-node --out-dir ./data --relay ws://127.0.0.1:8194 --shell-bin ./target/debug/igloo-shell
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools --offline -- e2e-full --threshold 11 --count 15 --shell-bin ./target/debug/igloo-shell
```

Wrapper scripts are also available:

```bash
scripts/devnet.sh gen
scripts/devnet.sh start
scripts/devnet.sh status
scripts/devnet.sh smoke
scripts/devnet-tmux.sh start
scripts/test-node-e2e.sh
```

## 6. Load A Profile

```bash
cargo run -p igloo-shell-cli -- profile load
```

`profile load` is now the normal way to unlock a local profile from the CLI:

- if you omit the profile id, the CLI shows a simple numbered profile picker
- after you pick a profile, the CLI prompts for the vault secret
- once the profile unlocks, `igloo-shell` prints profile status and next commands by default
- `profile load --start` starts the daemon and attaches to the daemon log
- `profile load --daemon` starts the daemon in the background and exits

You can also enter through the flow-specific top-level commands:

- `igloo-shell onboard <package-or-path>`
- `igloo-shell import <bfprofile-or-path>`
- `igloo-shell recover <bfshare-or-path>`
- `igloo-shell keygen`

Those commands collect their inputs in the CLI, then print the created profile and next commands on success. `onboard`, `import`, and `recover` support `--daemon` for background start and `--start` for immediate foreground attach.

Once a profile is running, the core operator surface is:

```bash
cargo run -p igloo-shell-cli -- daemon status --profile <profile-id>
cargo run -p igloo-shell-cli -- runtime status --profile <profile-id>
cargo run -p igloo-shell-cli -- peer list --profile <profile-id>
cargo run -p igloo-shell-cli -- policy show --profile <profile-id>
```

## Next Reading

- `V2-SHELL-SPEC.md`
- `OPERATIONS.md`
- `CONFIGURATION.md`
- `TESTING.md`
- `../../../docs/ARCHITECTURE.md`
