# Contributing

This file explains the local architecture and editing boundaries for `igloo-shell`.

## Repo Shape

`igloo-shell` keeps a small crate split:

- `crates/igloo-shell-core`
  - shell storage, manifests, encrypted-profile handling, daemon integration, package flows, and operator logic
- `crates/igloo-shell-cli`
  - clap surface, prompts, rendering, and integration tests around the public CLI

Keep business logic in `igloo-shell-core` and keep `main.rs` as thin wiring.

## Product Model

The shell is CLI-first. It has no TUI or session dashboard.

The first-class operator concepts are:

- profile
  - one local FROSTR device identity managed by the shell
- encrypted profile storage
  - encrypted local storage for secret artifacts
- daemon
  - one long-lived runtime process per profile
- relay profile
  - a named ordered relay set shared across profiles

Supported operator entrypoints are:

- `profile load`
- `onboard`
- `import`
- `recover`
- `rotate-key`
- `rotate-keyset`
- `keygen`

Behavioral rules to preserve:

- `recover` is recovery-only
- `rotate-key` is the in-place rotated-share adoption path
- `rotate-keyset` is the operator-side trusted rotation workflow
- no command should silently reintroduce a session UI model

## Storage Model

The shell uses XDG-backed roots:

```text
config: ${XDG_CONFIG_HOME:-~/.config}/igloo-shell
data:   ${XDG_DATA_HOME:-~/.local/share}/igloo-shell
state:  ${XDG_STATE_HOME:-~/.local/state}/igloo-shell
```

Storage responsibilities:

- config:
  - global shell config
  - relay profiles
  - profile manifests
- data:
  - managed non-secret group data
  - encrypted profile records
- state:
  - per-profile daemon metadata
  - signer/runtime state
  - logs, sockets, and runtime lock files

Do not regress toward plaintext managed share storage.

## Profile and Encrypted Profile Boundaries

A profile manifest is the stable operator-facing record for one local device. It binds together:

- one managed group package
- one local encrypted profile record
- one relay profile
- one runtime state directory
- one daemon socket path
- optional runtime and peer-policy overrides

Encrypted profile storage keeps secret artifacts encrypted at rest. Expected kinds include:

- `share_package`
- `onboarding_package`
- `import_bundle`

The shell owns:

- XDG storage layout
- profile manifests
- relay profile definitions
- encrypted profile encryption and unlock
- profile resolution
- daemon lifecycle from the CLI surface

The hosted runtime layer owns:

- live runtime hosting from resolved in-memory material
- control RPC and event transport
- persistence coordination for runtime-owned mutable state

## Runtime and Daemon Model

Each active profile runs in its own daemon/runtime instance.

Preserve these rules:

- daemons are per-profile, not multi-profile
- `profile load --start` is the explicit foreground attach path
- `--daemon` is the background-start convenience path
- starting an already running daemon is idempotent
- CLI process exit must not implicitly stop the daemon

Commands that need live runtime state should go through the daemon control surface rather than bypassing it.

## Package and Rotation Boundaries

Keep the simplified package model intact:

- `bfprofile`
  - import/export of a portable profile bundle
- `bfshare`
  - recovery material and operator rotation input only
- `bfonboard`
  - onboarding and rotated-share adoption artifact

Rotation rules to preserve:

- `rotate-key` applies a rotated `bfonboard` to an existing profile
- `rotate-keyset` gathers threshold `bfshare` inputs, rotates the keyset, replaces the local source profile, and emits remote `bfonboard` packages

## Editing Guidance

When making changes:

- keep CLI parsing and terminal UX in `igloo-shell-cli`
- keep storage, package, and daemon logic in `igloo-shell-core`
- prefer extending existing integration harness helpers instead of inventing new one-off scripts
- update root docs when the public shell contract changes
- do not add references to sibling repos or workspace-level docs in repo-local manuals

## Validation Expectations

Before landing non-trivial changes, run at least:

```bash
cargo check --workspace --offline
cargo test --workspace --offline
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
```
