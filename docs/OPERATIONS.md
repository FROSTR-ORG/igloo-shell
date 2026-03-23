# Operations

This manual covers shell-owned operator workflows for the hard-cut V2 shell.

## Current Active Surface

```bash
cargo run -p igloo-shell-cli -- profile list
cargo run -p igloo-shell-cli -- profile load
cargo run -p igloo-shell-cli -- profile load alice --start
cargo run -p igloo-shell-cli -- profile load alice --daemon
cargo run -p igloo-shell-cli -- onboard ./onboard-bob.txt --label bob --onboard-secret-file ./onboard-bob.password.txt --vault-secret-file ./vault-secret.txt --start
cargo run -p igloo-shell-cli -- profile backup alice --vault-passphrase-env IGLOO_SHELL_VAULT_PASSPHRASE
cargo run -p igloo-shell-cli -- onboard ./onboard-bob.txt --label bob --onboard-secret-file ./onboard-bob.password.txt --vault-secret-file ./vault-secret.txt
cargo run -p igloo-shell-cli -- import ./bob.bfprofile.txt --label bob --package-secret-file ./bob.package-secret.txt --vault-secret-file ./vault-secret.txt
cargo run -p igloo-shell-cli -- recover ./bob.bfshare.txt --label bob --package-secret-file ./bob.package-secret.txt --vault-secret-file ./vault-secret.txt
cargo run -p igloo-shell-cli -- keygen
cargo run -p igloo-shell-cli -- export alice --out ./exports/alice --format raw
cargo run -p igloo-shell-cli -- relays list
cargo run -p igloo-shell-cli -- relays set demo --label Demo ws://127.0.0.1:8194
cargo run -p igloo-shell-cli -- relays default demo
```

The shell store and CLI-first flow model are live. `profile load`, `onboard`, `import`, `recover`, and `keygen` are the supported profile entry paths. `profile load --start` is the explicit foreground daemon/log path, and `--daemon` is the background-start convenience flag for profile-producing flows. `V2-SHELL-SPEC.md` is the source of truth for the broader command surface.

The CLI replaces the old dashboard-style shell flow with explicit operator commands:

```bash
cargo run -p igloo-shell-cli -- daemon status --profile alice
cargo run -p igloo-shell-cli -- runtime status --profile alice
cargo run -p igloo-shell-cli -- peer list --profile alice
cargo run -p igloo-shell-cli -- policy show --profile alice
```

## Developer Utilities

```bash
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools -- keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools -- relay --host 127.0.0.1 --port 8194
cargo run -p igloo-shell-cli -- export alice --out ./bob.onboard.txt --format bfonboard --recipient-share <share.json> --package-password-env IGLOO_SHELL_PACKAGE_PASSWORD
cargo run -p igloo-shell-cli -- onboard ./onboard-bob.txt --label bob --onboard-secret-file ./onboard-bob.password.txt --vault-secret-file ./vault-secret.txt
cargo run -p igloo-shell-cli -- onboard ./onboard-bob.txt --label bob --onboard-secret-file ./onboard-bob.password.txt --vault-secret-file ./vault-secret.txt --json
```

## Dev E2E

```bash
cargo build -p igloo-shell-cli --bin igloo-shell --offline
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools --offline -- e2e-node --out-dir ./data --relay ws://127.0.0.1:8194 --shell-bin ./target/debug/igloo-shell
cargo run --manifest-path ../bifrost-rs/Cargo.toml -p bifrost-devtools --offline -- e2e-full --threshold 11 --count 15 --shell-bin ./target/debug/igloo-shell
```

Convenience wrappers:

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-$(date +%F).txt
```

## Observability

- The hard-cut shell store uses XDG config/data/state roots.
- Runtime logging and daemon observability are part of the live daemon-backed shell.

## Interactive Onboarding

- If `--label` is omitted on a TTY, `igloo-shell onboard` prompts for the profile name first.
- The onboarding package secret is prompted next.
- The vault secret prompt comes after package decryption succeeds, and requires confirmation.
- A successful interactive onboard prints the created profile and next commands.
- Add `--daemon` to onboard in order to start the new profile in the background immediately.
- Add `--start` to onboard in order to attach to the new profile's daemon log immediately.
