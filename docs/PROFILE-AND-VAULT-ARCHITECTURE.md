# Profile and Vault Architecture

This document defines the implementation architecture for shell-managed profiles, vault records, and daemon bootstrap in `igloo-shell`.

Use it together with `V2-SHELL-SPEC.md`:

- `V2-SHELL-SPEC.md` is the product and operator contract
- this document is the storage, lifecycle, and ownership design for implementers

## Summary

`igloo-shell` owns local device identity as a managed shell concept. Users operate on profiles, not raw config paths. Secret artifacts are stored in a shell-managed encrypted vault. The daemon resolves profile state into in-memory runtime bootstrap material and then hands that resolved material to `bifrost-app`.

The architecture separates three concerns:

- shell config storage: profile manifests, relay profiles, shell preferences
- shell vault storage: encrypted secret artifacts such as share packages
- runtime state storage: mutable signer/device state persisted by the daemon

## First-Class Objects

### Profile Manifest

A profile manifest is the stable operator-facing record for one local FROSTR V2 device.

It binds together:

- one managed group package
- one managed secret share record
- one relay profile
- one runtime state directory
- one daemon socket path
- optional runtime option overrides
- optional peer policy overrides

The CLI addresses profiles by id or label. It does not require users to pass raw config file paths for normal shell workflows.

### Vault Record

A vault record represents one encrypted secret artifact stored under shell control.

Expected kinds:

- `share_package`
- `onboarding_package`
- `import_bundle`

The shell vault is the only supported managed storage for secret artifacts. Managed plaintext share storage is not part of the target architecture.

### Relay Profile

A relay profile is a named ordered relay set shared across profiles. Profiles reference relay profiles instead of embedding relay lists everywhere.

### Daemon Metadata

Daemon metadata tracks one running per-profile daemon.

It includes:

- profile id
- pid
- control socket path
- control token
- log path
- start time

## Storage Layers

### 1. Shell Config Storage

Shell config storage is non-secret metadata under the XDG config root.

It includes:

- global shell config
- relay profile definitions
- profile manifests

This is the source of truth for what profiles exist and how the shell should resolve them.

### 2. Shell Vault Storage

Shell vault storage is secret material under the XDG data root.

It includes:

- imported share packages
- imported `bfonboard` packages before profile import completes
- any future shell-owned secret import bundles

Rules:

- payloads are encrypted at rest
- OS keyring is preferred when available
- passphrase fallback is supported
- the shell must never silently downshift to plaintext managed storage

### 3. Runtime State Storage

Runtime state storage is mutable operational state under the XDG state root.

It includes:

- persisted signer state
- daemon socket
- daemon log
- runtime lock/marker files
- daemon metadata

This state is owned by the running daemon and may change frequently. It is not the source of truth for imported identity material.

## Secret and Non-Secret Material

The shell treats artifacts as follows:

- group package: managed, non-secret
- share package: secret, vault-managed
- imported `bfonboard` package: secret until imported, vault-managed
- runtime signer state: operational state, encrypted/persisted by runtime rules
- relay profile and shell config: non-secret

This split is intentional. Group packages need management and discoverability, but they do not require the same secrecy guarantees as local share material.

## Lifecycle Flows

### Profile Import

`import` accepts either:

- a group package and share package
- an encrypted `bfprofile` package

Import flow:

1. validate input artifacts
2. store the group package in managed non-secret storage
3. encrypt and store the secret artifact in the vault
4. create or update the profile manifest
5. resolve the relay profile reference
6. prepare runtime state directories for that profile

After import, the shell has enough information to start a daemon without relying on a user-managed plaintext config file.

### Daemon Start

`daemon start --profile <id>` performs:

1. load the profile manifest
2. load the referenced relay profile
3. unlock the vault record referenced by `share_ref`
4. decrypt the secret material in memory
5. load the group package from managed storage
6. build resolved runtime bootstrap material
7. launch `bifrost-app` with that resolved material

The shell daemon never needs to persist decrypted share material to managed plaintext storage.

### Runtime Operations

After bootstrap, live operations go through:

- `igloo-shell`
- `bifrost-app`
- `bifrost-bridge-tokio::Bridge`
- `bifrost-router`
- `bifrost-signer`

The shell does not call the signer directly for live runtime actions.

### Profile Export

`export` is the explicit path for writing user-chosen output files.

Export flow:

1. resolve the profile
2. unlock and decrypt the vault record
3. materialize explicit export files in the chosen output directory
4. never mutate or delete unrelated user files outside shell-managed storage

Export is the only supported path where the shell intentionally writes plaintext secret artifacts.

### Profile Remove

`profile remove` deletes shell-managed records for that profile.

Rules:

- remove the manifest
- remove shell-owned state for that profile
- remove shell-owned vault records no longer referenced
- never delete user-managed exports outside the shell store

## Ownership Boundary

`igloo-shell-core` owns:

- XDG storage layout
- shell config and relay profiles
- vault encryption and unlock
- profile resolution
- daemon lifecycle from the shell UX

`bifrost-app` owns:

- runtime hosting from resolved in-memory material
- control RPC and event transport
- persistence coordination for live runtime state

`bifrost-rs` does not own:

- shell vault layout
- shell keyring behavior
- shell profile manifest semantics

## Hard-Cut Target

The target architecture is vault-backed profile manifests.

That means:

- `group_ref` points to managed group storage
- `share_ref` points to a vault-backed secret record
- plaintext path-based manifests are transitional or dev-only

Implementation may temporarily dual-read while migrating, but the supported end state is shell-managed profile and vault ownership.
