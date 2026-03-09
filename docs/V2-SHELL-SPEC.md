# igloo-shell V2 Shell Specification

This document is the build-ready product and implementation specification for the next-generation `igloo-shell` CLI and TUI. It defines the canonical user model, shell-managed local state, CLI namespaces, TUI behavior, hard-cut migration rules, and acceptance criteria for the FROSTR V2 shell experience.

## 1. Goals

`igloo-shell` must provide a rich operator and provisioning experience for FROSTR V2 without requiring users to manually compose low-level runtime commands. The shell becomes the human-facing control plane for:

- profile setup and import
- runtime daemon lifecycle
- peer diagnostics and protocol operations
- invite-based onboarding
- relay and policy management
- live runtime visibility through a full-screen TUI

The shell is V2-native. It may borrow successful interaction patterns from the older V1 `igloo-cli`, but command names, flows, and documentation are organized around the V2 runtime, per-profile daemons, invites, and runtime readiness.

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

The shell owns a managed local vault for secret artifacts. Imported share material, accepted onboarding packages before import, and similar sensitive artifacts are encrypted at rest by default. The vault is shell-managed and is not exposed as a raw plaintext file store.

### 2.3 Daemon

The daemon is the long-lived runtime process for a single profile. It is the canonical source of live state. CLI commands and the TUI connect to the daemon through a per-profile control socket when live runtime state is needed.

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
- `policy_overrides`
- `state_path`
- `daemon_socket_path`
- `last_used_at`
- `created_at`

Behavioral rules:

- `id` is stable and shell-generated.
- `label` is user-facing and mutable.
- `group_ref` points to a managed group package under `data/groups`.
- `share_ref` points to an encrypted vault record, not a plaintext share path.
- `runtime_options` mirrors supported host/runtime options already exposed through config and control APIs.
- `policy_overrides` mirrors peer policy overrides persisted for the profile.

### 4.3 Vault Record

Each secret vault record stores metadata plus an encrypted payload file.

Metadata fields:

- `id`
- `kind`
  Allowed values: `share_package`, `onboarding_package`, `import_bundle`
- `source`
  Allowed values: `file_import`, `invite_accept`, `shell_keygen`, `profile_export_roundtrip`
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

CLI and TUI clients use the daemon when they need:

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
- quitting the TUI never stops the daemon implicitly

### 5.3 Control Plane

The shell spec adopts the control operations already supported by the host layer as the live runtime API surface:

See `PROFILE-AND-VAULT-ARCHITECTURE.md` for the daemon bootstrap path and the boundary between shell-managed storage and `bifrost-app` runtime hosting.

- status
- policies
- set_policy
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

The CLI and TUI must render these as stable shell commands and screens rather than exposing raw control JSON to users.

## 6. CLI Surface

The new CLI surface is namespace-first. Top-level help must show the namespaces below.

### 6.1 `setup`

Purpose: guided first-run and import experience.

Required behaviors:

- if no profiles exist, offer create-from-files, import-onboarding-package, or use dev keygen
- allow relay profile selection or creation
- allow profile label selection
- unlock and validate imported secret material
- create managed profile records
- optionally start the daemon
- optionally launch the TUI on success

### 6.2 `profile`

Commands:

- `profile list`
- `profile show <profile-id>`
- `profile import --group <path> --share <path> [--label <label>] [--relay-profile <id>]`
- `profile import --onboarding-package <path> [--label <label>] [--relay-profile <id>]`
- `profile export <profile-id> --out-dir <path>`
- `profile remove <profile-id>`
- `profile doctor <profile-id>`

Rules:

- import converts file-based artifacts into managed shell records
- export writes explicit files chosen by the user and requires unlock
- remove never deletes exported user files outside the shell store
- doctor validates manifest integrity, vault accessibility, runtime state path, socket path, and relay profile references

### 6.3 `daemon`

Commands:

- `daemon start --profile <profile-id>`
- `daemon stop --profile <profile-id>`
- `daemon restart --profile <profile-id>`
- `daemon status [--profile <profile-id>]`
- `daemon logs --profile <profile-id> [--follow]`

Rules:

- `status` without `--profile` shows all known profile daemons
- `logs` reads structured daemon logs from the profile state directory
- `start` prints socket path, pid if known, profile id, and readiness summary

### 6.4 `runtime`

Commands:

- `runtime status --profile <profile-id>`
- `runtime readiness --profile <profile-id>`
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

### 6.5 `peer`

Commands:

- `peer list --profile <profile-id>`
- `peer ping --profile <profile-id> <peer-pubkey>`
- `peer onboard --profile <profile-id> <peer-pubkey> [--challenge-hex32 <hex>]`

Rules:

- `list` renders peer status from live runtime data, not static config alone
- peer rows include idx, pubkey, online, last seen, known, incoming nonce availability, outgoing nonce availability, sign readiness, and nonce-send expectation

### 6.6 `invite`

Commands:

- `invite create --profile <profile-id> [--relay <url> ...] [--expires-in-secs <n>] [--label <label>]`
- `invite list --profile <profile-id>`
- `invite show --profile <profile-id> <challenge-hex32>`
- `invite revoke --profile <profile-id> <challenge-hex32>`
- `invite assemble --token <token> --share <path> (--password-env <var> | --password-file <path> | --password-stdin | --generate-password)`
- `invite accept <package-or-path> (--password-env <var> | --password-file <path> | --password-stdin)`
- `invite import <package-or-path> [--label <label>] [--relay-profile <id>]`

Rules:

- `create`, `list`, `show`, and `revoke` are daemon-backed profile operations
- `assemble` and `accept` remain local artifact transforms
- `import` consumes an accepted onboarding package and creates a managed profile
- `show` renders one pending invite record with expiry, relay set, callback peer, label, and consumed state

### 6.7 `policy`

Commands:

- `policy show --profile <profile-id>`
- `policy set-default --profile <profile-id> --send <allow|block> --receive <allow|block>`
- `policy set-peer --profile <profile-id> <peer-pubkey> --send <allow|block> --receive <allow|block>`
- `policy clear-peer --profile <profile-id> <peer-pubkey>`

Rules:

- policies are persisted into the profile manifest and applied to the live daemon
- `show` displays defaults plus peer overrides
- a hidden compatibility command may still accept raw JSON, but raw JSON is not part of the primary documented surface

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

### 6.10 `tui`

Command:

- `tui [--profile <profile-id>]`

Rules:

- if no profile is given and multiple profiles exist, open a picker
- if the selected profile daemon is not running, offer start/connect/back
- the TUI never embeds a second direct runtime path; it always attaches to a daemon

### 6.11 `dev`

Commands:

- `dev keygen`
- `dev relay`
- `dev e2e-node`
- `dev e2e-full`

These preserve current developer tooling and devnet workflows. They are not the primary user-facing onboarding surface.

## 7. Hard-Cut Migration

The shell does not keep a public compatibility layer for the old command surface.

Rules:

- the namespace-based CLI in this document is the only supported public interface
- `listen`, `status`, `policies`, `set-policy`, `sign`, `ecdh`, `ping`, and `onboard` are removed as public commands
- the standalone `igloo-shell-tui` entrypoint is removed from the supported interface in favor of `igloo-shell tui`
- existing developer utilities remain available only under the `dev` namespace
- docs, examples, scripts, and tests move directly to the new surface

## 8. TUI Specification

The TUI is a full-screen operator console attached to one profile daemon.

### 8.1 Entry Behavior

- `tui --profile <id>` attaches directly
- `tui` opens a profile selector when multiple profiles exist
- if no profiles exist, the TUI opens the setup screen

### 8.2 Screens

The TUI has six primary sections:

- `Overview`
- `Peers`
- `Invites`
- `Policies`
- `Logs`
- `Setup`

### 8.3 Overview

Shows:

- profile label and id
- daemon status
- runtime device id
- threshold and group size if available
- runtime readiness flags
- degraded reasons
- pending operation count
- last refresh time

Actions:

- start daemon
- stop daemon
- restart daemon
- refresh runtime status
- jump to pending operations detail

### 8.4 Peers

Shows one row per peer with:

- idx
- shortened pubkey
- known flag
- online flag
- last seen
- incoming nonce availability
- outgoing nonce availability
- outgoing spent
- can sign
- should send nonces

Actions:

- ping selected peer
- onboard selected peer
- view full pubkey

### 8.5 Invites

Shows:

- label
- challenge hex
- relay set summary
- created time
- expiry time
- consumed state
- callback peer

Actions:

- create invite
- copy token
- show full token
- revoke invite
- import accepted onboarding package

### 8.6 Policies

Shows:

- default send/receive posture
- peer-specific overrides

Actions:

- edit defaults
- add peer override
- edit peer override
- clear peer override

### 8.7 Logs

Shows structured daemon events with:

- timestamp
- level
- short message
- compact summary derived from event payload

Behaviors:

- duplicate adjacent events are collapsed
- verbosity can be toggled
- logs are readable without leaving the TUI

### 8.8 Setup

Supports:

- import group/share files
- import accepted onboarding package
- export current profile
- choose relay profile
- view unlock status
- start daemon after import

### 8.9 Keybindings

Required keybindings:

- `Tab` / `Shift-Tab` move between sections
- arrow keys move within tables and menus
- `Enter` opens selected action
- `r` refreshes live state
- `l` toggles log visibility or log detail
- `s` starts or stops the daemon for the attached profile
- `q` quits the TUI client only

## 9. UX Rules

The CLI and TUI must follow these rules consistently.

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
- TUI runtime views consume control operations already available for status, peer status, readiness, runtime status, runtime metadata, config read/update, and wipe-state
- existing local invite assemble and accept utilities remain in place and are promoted into the new shell surface

### 11.2 Configuration Migration

Path-based dev configs generated by current `keygen` remain supported for developer workflows under `dev`. The managed profile store is additive and becomes the default user-facing path.

### 11.3 Logging

Daemons write structured logs per profile under the profile state directory. CLI `daemon logs` and the TUI log screen read from the same source.

## 12. Test and Acceptance Criteria

### 12.1 CLI Parsing and Help

- each new namespace parses correctly
- top-level help advertises the new namespaces
- removed commands are absent from top-level help

### 12.2 Vault and Profile Management

- import from group/share files creates a valid profile manifest and encrypted vault record
- import from accepted onboarding package creates a valid profile manifest and encrypted vault record
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
- runtime readiness renders degraded reasons when peer counts are insufficient
- peer list shows live peer data
- peer ping succeeds against a healthy devnet
- peer onboard succeeds with and without explicit challenge
- runtime sign returns signature output
- runtime ecdh returns shared secret output
- runtime wipe-state requires confirmation and completes through the live daemon

### 12.5 Invite Lifecycle

- invite create returns a usable token
- invite list and show render pending invite details
- invite revoke removes or marks the invite correctly
- invite assemble produces an onboarding package
- invite accept decodes the onboarding package correctly
- invite import creates a usable managed profile

### 12.6 TUI

- TUI opens profile picker when needed
- TUI overview renders readiness and pending operation state
- TUI peers screen can run ping and onboard actions
- TUI invites screen can create and revoke invites
- TUI policies screen can edit defaults and peer overrides
- quitting the TUI does not stop the daemon

## 13. Default Decisions

The following decisions are fixed by this spec and should not be reopened during implementation unless blocked by a concrete technical issue.

- runtime model is daemon-first
- topology is one daemon per active profile
- local secret material is shell-managed and encrypted at rest
- command surface is V2-native and namespace-based
- TUI is an operator console, not a wizard-only app
- the shell balances operator workflows and provisioning flows
- existing devnet tooling remains available under `dev`
- Unix domain sockets are the initial daemon transport

## 14. Deliverables

Implementation is complete when:

- the new CLI namespaces exist and are documented
- profile and vault storage exist with encrypted secret handling
- per-profile daemons can be started and queried
- the TUI attaches to daemons and exposes the specified screens
- automated tests cover the acceptance criteria above
