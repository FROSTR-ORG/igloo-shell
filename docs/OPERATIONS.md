# Operations

This manual covers shell-owned operator workflows for the hard-cut V2 shell.

## Current Active Surface

```bash
cargo run -p igloo-shell-cli -- profile list
cargo run -p igloo-shell-cli -- relays list
cargo run -p igloo-shell-cli -- relays set demo --label Demo ws://127.0.0.1:8194
cargo run -p igloo-shell-cli -- relays default demo
```

The shell store and namespace-based CLI are live. The daemon/runtime/profile-import side of the hard cut is still being wired. `V2-SHELL-SPEC.md` is the source of truth for the final command surface.

## Developer Utilities

```bash
cargo run -p igloo-shell-cli -- dev keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
cargo run -p igloo-shell-cli -- dev relay --host 127.0.0.1 --port 8194
cargo run -p igloo-shell-cli -- invite assemble --token '<invite-token-json>' --share <share.json> --password-env INVITE_PASSWORD
cargo run -p igloo-shell-cli -- invite accept <bfonboard1...> --password-env INVITE_PASSWORD
```

## Dev E2E

```bash
cargo run -p igloo-shell-cli --offline -- dev e2e-node --out-dir ./data --relay ws://127.0.0.1:8194
cargo run -p igloo-shell-cli --offline -- dev e2e-full --threshold 11 --count 15
```

Convenience wrappers:

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-$(date +%F).txt
```

## Observability

- The hard-cut shell store uses XDG config/data/state roots.
- Runtime logging and daemon observability will arrive with the daemon slice.
