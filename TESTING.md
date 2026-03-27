# Testing

`igloo-shell` owns CLI, daemon, and runtime smoke coverage for the shell project.

## Fast Baseline

Run this before pushing changes:

```bash
cargo fmt --all -- --check
cargo check --workspace --offline
cargo test --workspace --offline
```

## Primary Rust Integration Targets

The shell contract is primarily locked by Rust integration tests:

```bash
cargo test -p igloo-shell-cli --test managed_integration --offline
cargo test -p igloo-shell-cli --test utility_integration --offline
cargo test -p igloo-shell-cli --test policy_integration --offline
```

These targets cover:

- profile load and daemon-start routing
- onboarding, import, recovery, key generation, export, and backup
- `rotate-key` adoption
- `rotate-keyset` operator rotation
- daemon, runtime, relays, peer, policy, and utility command families
- managed runtime integration for ping, onboarding, signing, and ECDH

## Scripted Runtime Checks

Run the repo-owned smoke and node E2E layers with:

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
```

What they validate:

- `scripts/devnet.sh smoke`
  - profile doctor
  - daemon and runtime status
  - peer listing
  - sign and ECDH readiness
  - canonical onboarding export/import flow on managed profiles
- `scripts/test-node-e2e.sh`
  - managed profile provisioning
  - per-profile daemon startup
  - sign and peer-loop checks
  - `bfshare` recovery
  - `rotate-keyset` generation
  - `rotate-key` and onboarding adoption paths

## Soak and Heavy Stress

Longer-running checks:

```bash
scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-$(date +%F).txt
cargo test -p igloo-shell-cli --test managed_stress --offline -- --ignored
```

Use these for nightly or manual validation, not as the default fast path.

## Expected Validation Split

- Rust integration tests:
  - primary gated shell contract
- repo scripts:
  - CLI and runtime smoke across managed profiles
- soak and ignored stress:
  - heavier manual confidence checks
