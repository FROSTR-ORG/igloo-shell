# Testing

`igloo-shell` owns shell/operator runtime integration checks.

## Fast Baseline

```bash
cargo fmt --all -- --check
cargo check --workspace --offline
cargo test --workspace --offline
```

## Scripted Runtime Checks

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-$(date +%F).txt
```

`scripts/devnet.sh` is now managed-profile aware:

- `gen` creates dev material, relay profile `local`, and managed profiles for `alice`, `bob`, and `carol`
- `start` launches the relay plus three per-profile daemons
- `start-responders` launches the relay plus `bob` and `carol`
- `status` queries daemon status through the public shell surface
- `smoke` runs profile doctor, runtime status, peer listing, signing, and invite create/revoke on the managed path

`scripts/test-node-e2e.sh` now validates the release CLI path rather than the old config-file host path:

- provisions managed profiles through `scripts/devnet.sh`
- starts the per-profile daemons
- checks profile doctor, daemon status, runtime status, and peer list
- executes a real sign request and invite create/show/revoke flow

`scripts/ws_soak.sh` now combines:

- `bifrost-rs` bridge and signer fault-injection regressions from the `bifrost-rs` workspace
- the migrated `igloo-shell dev e2e-full` managed-profile stress harness

`scripts/test-tui-e2e.sh` now exercises the managed-profile daemon-backed path:

- starts a local relay
- imports a managed profile into XDG shell storage
- starts the per-profile daemon
- launches `igloo-shell tui --profile <id>` in `tmux`
- sends screen-navigation and invite-creation keys
- captures the pane and asserts on rendered screen content

## Direct Runtime E2E

```bash
cargo run -p igloo-shell-cli --offline -- dev e2e-node --out-dir ./dev/data --relay ws://127.0.0.1:8194
cargo run -p igloo-shell-cli --offline -- dev e2e-full --threshold 11 --count 15
```
