# Testing

`igloo-shell` owns shell/operator runtime integration checks.

## Fast Baseline

```bash
cargo fmt --all -- --check
cargo check --workspace --offline
cargo test --workspace --offline
```

PR-gated Rust coverage now includes:

- public CLI `onboard` integration coverage for interactive-resolution logic, `--onboard-secret`, `--onboard-secret-file`, `--vault-secret`, `--vault-secret-file`, and inline package flows
- public CLI coverage for `profile load` routing, daemon-start flags, and post-import/recover/onboard/keygen next-command output
- public CLI foreground-start coverage for `import --start`, `recover --start`, and `onboard --start`
- public CLI rotation-update coverage for `rotate-key`, `rotate-key --daemon`, and `rotate-key --start`
- public CLI operator-rotation coverage for `rotate-keyset init`, `rotate-keyset show`, and `rotate-keyset generate`
- managed runtime integration coverage for ping, peer onboarding, signing, ECDH, and invite lifecycle
- live policy command coverage for manifest persistence and daemon-backed runtime updates

Run those targets directly with:

```bash
cargo test -p igloo-shell-cli --test managed_integration --offline
cargo test -p igloo-shell-cli --test policy_integration --offline
```

## Scripted Runtime Checks

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
../../run.sh demo smoke
scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-$(date +%F).txt
```

`scripts/devnet.sh` is now managed-profile aware:

- `gen` creates dev material, relay profile `local`, and managed profiles for `alice`, `bob`, and `carol`
- `start` launches the relay plus three per-profile daemons
- `start-responders` launches the relay plus `bob` and `carol`
- `status` queries daemon status through the public shell surface
- `smoke` runs profile doctor, runtime status, peer listing, signing, and canonical onboarding export/import on the managed path

`scripts/test-node-e2e.sh` now validates the release CLI path rather than the old config-file host path:

- provisions managed profiles through `scripts/devnet.sh`
- starts the per-profile daemons
- checks profile doctor, daemon status, runtime status, and peer list
- executes a real sign request, canonical `bfonboard` export/onboard flow, and operator-side `rotate-keyset` generation flow

`scripts/ws_soak.sh` now combines:

- `bifrost-rs` bridge and signer fault-injection regressions from the `bifrost-rs` workspace
- the migrated `bifrost-devtools e2e-full` managed-profile stress harness

`../../run.sh demo smoke` validates the host-side demo path:

- starts `dev-relay` plus `igloo-demo` under a temporary compose project
- reads the generated onboarding package and password file from the harness artifacts
- imports a fresh local managed profile with `igloo-shell onboard --label demo-smoke --onboard-secret-file --vault-secret-file --json`
- starts the local daemon and verifies runtime status plus peer visibility through the exposed relay

## Direct Runtime E2E

```bash
cargo build -p igloo-shell-cli --bin igloo-shell --offline
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools --offline -- e2e-node --out-dir ./dev/data --relay ws://127.0.0.1:8194 --shell-bin ./target/debug/igloo-shell
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools --offline -- e2e-full --threshold 11 --count 15 --shell-bin ./target/debug/igloo-shell
```

The heavy `11-of-15` managed stress regression is also available as an ignored Rust test for
nightly/manual CI:

```bash
cargo test -p igloo-shell-cli --test managed_stress --offline -- --ignored
```

`bifrost-devtools e2e-full` now covers:

- managed profile provisioning and daemon startup
- peer discovery, pinging, and onboarding
- policy `set-default-override` / `set-peer-override` / `clear-peer` round trips
- repeated signing and ECDH iterations
