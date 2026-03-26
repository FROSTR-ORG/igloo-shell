# igloo-shell V2 Shell Specification

This document is the build-ready product and implementation specification for the next-generation `igloo-shell` CLI. It defines the canonical user model, shell-managed local state, CLI namespaces, daemon behavior, hard-cut migration rules, and acceptance criteria for the FROSTR V2 shell experience.

## 1. Goals

`igloo-shell` must provide a rich operator and provisioning experience for FROSTR V2 without requiring users to manually compose low-level runtime commands. The shell becomes the human-facing control plane for:

- profile setup and import
- runtime daemon lifecycle
- peer diagnostics and protocol operations
- package-based onboarding
- relay and policy management
- live runtime visibility through daemon-backed CLI commands and logs

The shell is V2-native. It may borrow successful interaction patterns from the older V1 `igloo-cli`, but command names, flows, and documentation are organized around the V2 runtime, per-profile daemons, package flows, and runtime-owned status.

## 2. Product Model

The shell operates around four first-class concepts.

Implementation detail for these concepts is defined in `PROFILE-AND-VAULT-ARCHITECTURE.md`.

### 2.1 Profile

A profile represents one local FROSTR V2 device identity and its runtime configuration. A profile binds together:

- one group package
- one local share package
- one encrypted runtime state path
- one relay profile
- zero or more local policy overrides
- one daemon socket path

Each active profile runs in its own daemon/runtime instance.

### 2.2 Vault

The shell owns a managed local vault for secret artifacts. Imported share material, imported `bfonboard` packages before profile creation, and similar sensitive artifacts are encrypted at rest by default. The vault is shell-managed and is not exposed as a raw plaintext file store.

### 2.3 Daemon

The daemon is the long-lived runtime process for a single profile. It is the canonical source of live state. CLI commands connect to the daemon through a per-profile control socket when live runtime state is needed.

### 2.4 Relay Profile

A relay profile is a named, ordered set of relay URLs. Profiles reference relay profiles instead of embedding ad hoc relay lists everywhere. A default relay profile may be set for new profiles.

## 3. Scope and Non-Goals

This specification covers the shell experience only. It does not redefine FROSTR V2 wire formats or `bifrost-rs` protocol behavior.

Out of scope for this phase:

- Windows-native daemon transport
- multi-profile supervisor daemon
- desktop GUI
- remote daemon management across machines
- protocol-level changes in `bifrost-rs`

## 4. Storage Model

The shell uses XDG-style directories.

See `PROFILE-AND-VAULT-ARCHITECTURE.md` for storage ownership, secrecy boundaries, and lifecycle rules for these paths.

```text
config: ${XDG_CONFIG_HOME:-~/.config}/igloo-shell
data:   ${XDG_DATA_HOME:-~/.local/share}/igloo-shell
state:  ${XDG_STATE_HOME:-~/.local/state}/igloo-shell
```

Required layout:

```text
config/
  config.json
  relay-profiles.json
  profiles/
    <profile-id>.json

data/
  groups/
    <group-id>.json
  vault/
    <vault-record-id>.enc
  imports/
    <import-id>.json

state/
  profiles/
    <profile-id>/
      signer-state.json
      daemon.sock
      daemon.log
      runtime.lock
```

The shell may store additional derived indexes, but the files above are the stable contract.

### 4.1 Global Config

`config.json` stores:

- schema version
- default relay profile id
- keyring preference
- fallback unlock mode
- last used profile id

### 4.2 Profile Manifest

Each `profiles/<profile-id>.json` file stores:

- `id`
- `label`
- `group_ref`
- `share_ref`
- `relay_profile`
- `runtime_options`
- `manual_peer_policy_overrides`
- `remote_peer_policy_observations`
- `state_path`
- `daemon_socket_path`
- `last_used_at`
- `created_at`

Behavioral rules:

- `id` is the canonical derived `profile_id`.
- `label` is user-facing and mutable.
- `group_ref` points to a managed group package under `data/groups`.
- `share_ref` points to an encrypted vault record, not a plaintext share path.
- `runtime_options` mirrors supported host/runtime options already exposed through config and control APIs.
- `manual_peer_policy_overrides` persists local operator overrides.
- `remote_peer_policy_observations` persists the last ping-reported remote policy observations.

### 4.3 Vault Record

Each secret vault record stores metadata plus an encrypted payload file.

Metadata fields:

- `id`
- `kind`
  Allowed values: `share_package`, `onboarding_package`, `import_bundle`
- `source`
  Allowed values: `file_import`, `bfonboard_import`, `shell_keygen`, `profile_export_roundtrip`
- `ciphertext_path`
- `key_source`
  Allowed values: `os_keyring`, `passphrase`
- `created_at`
- `updated_at`

Payload rules:

- payload files are encrypted at rest
- the shell must prefer OS keyring-backed unlock when available
- the shell must support passphrase fallback when keyring is unavailable or disabled
- the shell must never silently downshift to plaintext storage

## 5. Runtime Architecture

### 5.1 Canonical Runtime Model

`daemon start --profile <id>` launches one long-lived runtime for that profile by wrapping the existing `listen --control-socket --control-token` host model.

The daemon owns:

- the live `bifrost-rs` bridge instance
- periodic runtime state persistence
- control socket request handling
- structured runtime logging

CLI commands use the daemon when they need:

- runtime status
- readiness
- peer status
- pending operations
- sign or ecdh execution
- peer ping or onboard actions
- policy updates against a live runtime
- runtime config reads or updates
- wipe-state

### 5.2 Per-Profile Topology

Only one daemon may run for a given profile at a time.

Rules:

- daemons are per-profile, not multi-profile
- socket path is deterministic from profile id
- starting an already running daemon is idempotent and returns the current status
- stopping a daemon persists state before exit when possible
- CLI process exit never stops the daemon implicitly

### 5.3 Control Plane

The shell spec adopts the control operations already supported by the host layer as the live runtime API surface:

See `PROFILE-AND-VAULT-ARCHITECTURE.md` for the daemon bootstrap path and the boundary between shell-managed storage and `bifrost-app` runtime hosting.

- status
- runtime_status
- set_manual_peer_policy_override
- clear_peer_policy_overrides
- ping
- onboard
- sign
- ecdh
- read_config
- update_config
- peer_status
- readiness
- runtime_status
- runtime_metadata
- wipe_state

The CLI must render these as stable shell commands rather than exposing raw control JSON to users.

## 6. CLI Surface

The new CLI surface is namespace-first. Top-level help must show the namespaces below.

### 6.1 `setup`

Purpose: guided first-run and import experience.

Required behaviors:

- if no profiles exist, offer create-from-files, `onboard`, or use external dev tooling to generate material
- allow relay profile selection or creation
- allow profile label selection
- unlock and validate imported secret material
- create managed profile records
- optionally start the daemon

### 6.2 `profile`

Commands:

- `profile list`
- `profile show <profile-id>`
- `profile load [<profile-id>]`
- `profile backup <profile-id>`
- `profile remove <profile-id>`
- `profile doctor <profile-id>`

Rules:

- remove never deletes exported user files outside the shell store
- doctor validates manifest integrity, vault accessibility, runtime state path, socket path, and relay profile references

### 6.2a `profile load`

Commands:

- `profile load`
- `profile load <profile-id>`
- `profile load [<profile-id>] [--vault-secret <value> | --vault-secret-file <path>]`
- `profile load [<profile-id>] --start`
- `profile load [<profile-id>] --daemon`

Rules:

- `profile load` is the canonical way to unlock a managed profile from the CLI
- without a profile id, `profile load` presents a CLI profile picker
- `profile load` prompts for the vault secret when no explicit secret source is provided
- default `profile load` validates vault unlock, prints status and next commands, and exits
- `--start` starts the daemon and attaches to daemon log output
- `--daemon` starts the daemon in the background and exits after printing status

### 6.2b `import`

Commands:

- `import <bfprofile-or-path> [--label <label>]`
- `import <bfprofile-or-path> --package-secret <value> --vault-secret <value> [--label <label>]`
- `import <bfprofile-or-path> --package-secret-file <path> --vault-secret-file <path> [--label <label>]`
- `import <bfprofile-or-path> ... --start`
- `import <bfprofile-or-path> ... --daemon`

Rules:

- import converts an encrypted `bfprofile` payload into a managed shell profile
- `import` prompts for any missing label or secret inputs on a TTY
- a successful import prints the resulting profile and next commands unless `--json` is supplied
- `--start` starts the resulting profile and attaches to daemon log output
- `--daemon` starts the resulting profile in the background after import completes

### 6.2c `recover`

Commands:

- `recover <bfshare-or-path> [--label <label>]`
- `recover <bfshare-or-path> --package-secret <value> --vault-secret <value> [--label <label>]`
- `recover <bfshare-or-path> --package-secret-file <path> --vault-secret-file <path> [--label <label>]`
- `recover <bfshare-or-path> ... --start`
- `recover <bfshare-or-path> ... --daemon`

Rules:

- recover resolves a `bfshare` payload into a managed profile using the latest published backup
- `recover` prompts for any missing label or secret inputs on a TTY
- a successful recovery prints the resulting profile and next commands unless `--json` is supplied
- `--start` starts the resulting profile and attaches to daemon log output
- `--daemon` starts the resulting profile in the background after recovery completes
- `recover` is recovery-only and does not replace an existing profile in place

### 6.2d `rotate-key`

Commands:

- `rotate-key <package-or-path> --profile <profile-id>`
- `rotate-key <package-or-path> --profile <profile-id> --onboard-secret <value> --vault-secret <value>`
- `rotate-key <package-or-path> --profile <profile-id> --onboard-secret-file <path> --vault-secret-file <path>`
- `rotate-key <package-or-path> ... --start`
- `rotate-key <package-or-path> ... --daemon`
- `rotate-key <package-or-path> ... --json`

Rules:

- `rotate-key` applies a rotated `bfonboard` package to an existing local profile
- `--profile` is required and identifies the local profile to replace
- `<package-or-path>` accepts either a file path or an inline `bfonboard...` payload
- a successful rotation update replaces the selected profile with a new profile id while preserving the intended local label and runtime options
- `--start` starts the replacement profile and attaches to daemon log output
- `--daemon` starts the replacement profile in the background after replacement completes
- `--json` keeps the command in automation/json mode

### 6.2e `rotate-keyset`

Commands:

- `rotate-keyset init --profile <profile-id> --threshold <n> --count <n>`
- `rotate-keyset init ... --workspace <path>`
- `rotate-keyset init ... --source-bfshare <path>...`
- `rotate-keyset init ... --vault-secret <value>`
- `rotate-keyset init ... --vault-secret-file <path>`
- `rotate-keyset show --workspace <path>`
- `rotate-keyset show --workspace <path> --json`
- `rotate-keyset generate --workspace <path>`
- `rotate-keyset generate ... --vault-secret <value> --distribution-secret <value>`
- `rotate-keyset generate ... --vault-secret-file <path> --distribution-secret-file <path>`
- `rotate-keyset generate ... --start`
- `rotate-keyset generate ... --daemon`
- `rotate-keyset generate ... --json`

Rules:

- `rotate-keyset` is the first-class operator workflow for trusted share rotation in `igloo-shell`
- `init` creates a workspace manifest at `<workspace>/rotation.json`
- the workspace manifest records:
  - source profile id, group id, and group public key
  - the next threshold/count
  - threshold `bfshare` source package paths plus env/file secret references
  - one target entry per rotated member
- `init` derives the default local replacement target from the selected source profile and current member index
- `show` reports structural readiness for the workspace without mutating state
- `generate`:
  - validates the threshold `bfshare` inputs
  - reconstructs the existing signing key
  - rotates the keyset while preserving the same group public key
  - replaces the selected local source profile immediately
  - publishes rotated encrypted backups
  - emits `bfonboard` packages for every non-local rotated target
- `generate --start` starts the replacement local profile and attaches to daemon log output
- `generate --daemon` starts the replacement local profile in the background after generation completes
- `generate --json` returns the local replacement summary plus emitted remote package paths
- `rotate-keyset` is the enterprise/operator-side generation path; `rotate-key` remains the device-side in-place adoption path

### 6.2f `export`

Commands:

- `export <profile-id> --out <path> [--format raw|bfprofile|bfshare|bfonboard]`

Rules:

- export writes explicit files chosen by the user and remains CLI-only
- canonical onboarding artifacts are emitted through `export --format bfonboard`

### 6.2g `onboard`

Commands:

- `onboard <package-or-path> [--label <label>]`
- `onboard <package-or-path> --onboard-secret <value> --vault-secret <value> [--label <label>]`
- `onboard <package-or-path> --onboard-secret-file <path> --vault-secret-file <path> [--label <label>]`
- `onboard <package-or-path> ... --start`
- `onboard <package-or-path> ... --daemon`
- `onboard <package-or-path> ... --json`

Rules:

- onboarding packages are imported through `onboard`, not `profile import`
- `<package-or-path>` accepts either a file path or an inline `bfonboard...` payload
- if `--label` is omitted on a TTY, `onboard` prompts for the profile name before any secret prompts
- if `--label` is omitted on a non-TTY, `onboard` fails and requires `--label`
- default behavior prompts for onboarding-secret input first, then vault-secret input, both without echo
- vault-secret interactive entry requires a confirmation prompt
- exactly one explicit onboarding-secret source may be supplied: `--onboard-secret` or `--onboard-secret-file`
- exactly one explicit vault-secret source may be supplied: `--vault-secret` or `--vault-secret-file`
- a successful onboard creates a managed profile and prints the next commands by default
- `--start` starts the resulting profile and attaches to daemon log output
- `--daemon` starts the resulting profile in the background after onboarding completes
- `--json` keeps the command in automation/json mode

### 6.2h `keygen`

Commands:

- `keygen`
- `keygen --keyset-name <name> --threshold <n> --count <n> --member-index <n> --label <label> --relay-url <url>...`

Rules:

- keyset generation is launched from the CLI
- the CLI collects the local member selection, vault secret, and onboarding-package distribution secret
- a successful keygen creates the local managed profile, writes onboarding packages for the remaining shares, and prints the next commands unless `--json` is supplied

### 6.3 `daemon`

Commands:

- `daemon stop --profile <profile-id>`
- `daemon restart --profile <profile-id>`
- `daemon status [--profile <profile-id>]`
- `daemon logs --profile <profile-id> [--follow]`

Rules:

- `status` without `--profile` shows all known profile daemons
- `logs` reads structured daemon logs from the profile state directory
- `start` prints socket path, pid if known, profile id, and readiness summary
- `load` unlocks profiles before daemon start and may auto-start a stopped daemon when `--start` or `--daemon` is supplied

### 6.4 `runtime`

Commands:

- `runtime status --profile <profile-id>`
- `runtime ops --profile <profile-id>`
- `runtime sign --profile <profile-id> <message-hex32>`
- `runtime ecdh --profile <profile-id> <pubkey-hex32>`
- `runtime wipe-state --profile <profile-id>`

Rules:

- all commands require a running daemon except when explicitly documented otherwise
- `ops` renders pending operations with request id, op type, start time, timeout, target peers, threshold, and collected responses summary
- `sign` prints the first signature by default and supports `--json` for full result
- `ecdh` prints the shared secret hex by default and supports `--json`
- `wipe-state` requires explicit confirmation unless `--yes` is supplied

### 6.5 `check`

Commands:

- `check onboard --profile <profile-id>`
- `check sign --profile <profile-id>`
- `check ecdh --profile <profile-id>`

Rules:

- `check` is the canonical public readiness surface
- `check onboard` reports inviter/device readiness and must not be blocked by sign/ecdh peer-count degradation alone
- `check sign` and `check ecdh` derive their results from signer-owned readiness and readiness explanation data
- all checks return machine-readable reasons when not ready

### 6.6 `peer`

Commands:

- `peer list --profile <profile-id>`
- `peer ping --profile <profile-id> <peer-pubkey>`
- `peer onboard --profile <profile-id> <peer-pubkey>`

Rules:

- `list` renders peer status from live runtime data, not static config alone
- peer rows include idx, pubkey, online, last seen, known, incoming nonce availability, outgoing nonce availability, sign readiness, and nonce-send expectation

### 6.6 `bfonboard`

Commands:

- `export <profile> --format bfonboard --recipient-share <path> --package-password-env <var>`

Rules:

- canonical onboarding artifacts are emitted only through `export --format bfonboard`
- the exported package carries the recipient share secret, relay set, and callback peer pubkey
- no legacy invite assembly or invite-token artifact flow remains

### 6.7 `policy`

Commands:

- `policy show --profile <profile-id>`
- `policy set-default-override --profile <profile-id> --direction <request|respond> --method <ping|onboard|sign|ecdh> --value <unset|allow|deny>`
- `policy set-peer-override --profile <profile-id> <peer-pubkey> --direction <request|respond> --method <ping|onboard|sign|ecdh> --value <unset|allow|deny>`
- `policy clear-peer --profile <profile-id> <peer-pubkey>`

Rules:

- manual peer policy overrides and remote peer policy observations are persisted into the profile manifest and applied to the live daemon
- `show` displays default overrides plus peer overrides using the per-method request/respond matrix
- no coarse `send` / `receive` policy commands remain in the primary CLI surface

### 6.8 `relays`

Commands:

- `relays list`
- `relays set <relay-profile-id> <url>...`
- `relays add <relay-profile-id> <url>...`
- `relays remove <relay-profile-id> <url>...`
- `relays test [--relay-profile <id>]`

Rules:

- relay URLs are stored in named relay profiles
- one relay profile may be the default for new profiles
- `test` performs connectivity validation and renders per-relay success or failure

### 6.9 `keys`

Commands:

- `keys convert --from <nsec|npub|hex-private|hex-public> --value <value>`

This exists for operator convenience and remains a local stateless utility.

### 6.10 Developer Tooling

Developer relay, keygen, and e2e orchestration live in `bifrost-devtools`, not in `igloo-shell`.

## 7. Hard-Cut Migration

The shell does not keep a public compatibility layer for the old command surface.

Rules:

- the namespace-based CLI in this document is the only supported public interface
- `listen`, `status`, `policies`, `set-policy`, `sign`, `ecdh`, `ping`, and `onboard` are removed as public commands
- existing developer utilities remain available only under the `dev` namespace
- docs, examples, scripts, and tests move directly to the new surface

## 8. CLI-Only Operator Contract

`igloo-shell` is now CLI-only.

Required behavior:

- `profile load` is the canonical shell entrypoint for unlocking a local profile
- `profile load --start` starts the daemon and attaches to daemon log output
- `profile load --daemon` starts the daemon in the background and exits
- successful onboarding/import/recover/keygen flows print the resulting profile and next commands by default
- `import`, `recover`, `onboard`, `rotate-key`, and `rotate-keyset generate` may use `--start` or `--daemon` to begin daemon execution immediately
- daemon logs are viewed through CLI output or `daemon logs`
- daemon status, runtime status, peer visibility, and policy inspection are all exposed through first-class CLI commands rather than a session dashboard

## 9. UX Rules

The CLI must follow these rules consistently.

- prefer human-readable summaries by default and `--json` for machine-friendly output
- never require users to know raw socket paths
- never expose plaintext secret material unless the user explicitly runs export or load-style commands
- render live runtime data from the daemon when available instead of stale manifest data
- keep dev-only concepts under `dev`
- keep V2 runtime concepts visible: readiness, degraded reasons, pending operations, invite lifecycle

## 10. Error Handling

The shell must produce explicit operator-friendly errors for:

- missing profile id
- missing or locked vault record
- keyring unavailable with no passphrase fallback configured
- daemon not running for daemon-backed commands
- stale or missing socket path
- invalid relay profile reference
- invalid onboarding package password
- profile manifest integrity mismatch
- runtime degraded due to insufficient signing or ecdh peers

CLI error messages must state:

- what failed
- which profile or artifact was involved
- whether retry, unlock, import repair, or daemon start is the next action

## 11. Implementation Requirements

### 11.1 Existing Runtime Reuse

Implementation must reuse existing host/runtime capabilities already present in the repo wherever possible.

Specifically:

- per-profile daemons wrap the existing host `listen` command with control socket support
- runtime-facing CLI commands consume control operations already available for status, peer status, readiness, runtime status, runtime metadata, config read/update, and wipe-state
- canonical `bfonboard` export/import is part of the shell surface

### 11.2 Configuration Migration

Path-based dev configs generated by current `keygen` remain supported for developer workflows under `dev`. The managed profile store is additive and becomes the default user-facing path.

### 11.3 Logging

Daemons write structured logs per profile under the profile state directory. CLI `daemon logs` reads from that source.

## 12. Test and Acceptance Criteria

### 12.1 CLI Parsing and Help

- each new namespace parses correctly
- top-level help advertises the new namespaces
- removed commands are absent from top-level help

### 12.2 Vault and Profile Management

- import from group/share files creates a valid profile manifest and encrypted vault record
- import from encrypted `bfonboard` package creates a valid profile manifest and encrypted vault record
- export requires unlock and writes usable files
- wrong passphrase fails without partial plaintext output
- doctor reports missing group, broken vault record, invalid relay profile, and stale state paths

### 12.3 Daemon Lifecycle

- daemon start is idempotent per profile
- daemon stop persists state before exit when possible
- daemon status reports running and stopped profiles correctly
- multiple profiles can run separate daemons at the same time

### 12.4 Runtime Operations

- runtime status renders device status for a running daemon
- `check onboard` reports relay and inviter readiness for demo/live onboarding
- `check sign` and `check ecdh` report capability and missing peers
- peer list shows live peer data
- peer ping succeeds against a healthy devnet
- peer onboard succeeds against a healthy devnet
- runtime sign returns signature output
- runtime ecdh returns shared secret output
- runtime wipe-state requires confirmation and completes through the live daemon

### 12.5 Onboarding Package Lifecycle

- `export --format bfonboard` produces a usable onboarding package
- onboard decodes the canonical onboarding package correctly
- onboard creates a usable managed profile

### 12.6 CLI Start Modes

- `profile load --start` attaches to daemon logs
- `profile load --daemon` starts the daemon in the background
- `import --start`, `recover --start`, and `onboard --start` attach to daemon logs after profile creation
- `import --daemon`, `recover --daemon`, and `onboard --daemon` start the daemon in the background after profile creation

## 13. Default Decisions

The following decisions are fixed by this spec and should not be reopened during implementation unless blocked by a concrete technical issue.

- runtime model is daemon-first
- topology is one daemon per active profile
- local secret material is shell-managed and encrypted at rest
- command surface is V2-native and namespace-based
- the shell balances operator workflows and provisioning flows
- existing devnet tooling remains available under `dev`
- Unix domain sockets are the initial daemon transport

## 14. Deliverables

Implementation is complete when:

- the new CLI namespaces exist and are documented
- profile and vault storage exist with encrypted secret handling
- per-profile daemons can be started and queried
- automated tests cover the acceptance criteria above
