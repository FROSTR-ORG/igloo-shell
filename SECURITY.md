# Security model

`igloo-shell` is the CLI-first operator host for FROSTR. This file
documents the host-local security boundary the shell relies on, and the
hardening contract added in Bucket C of the 2026-04-22 remediation track.

## Trust boundary

The shell treats **same-UID processes as trusted**. Any process running
under the operator's UID can:

- read profile manifests, encrypted profile records, and daemon metadata
  files (mode `0o600`, accessible only to the owner);
- connect to a running daemon's Unix socket (mode `0o600`, parent dir
  `0o700`);
- read the daemon's environment via `/proc/<pid>/environ` (though no
  passphrase is ever stored there post-PR12).

Hardening **against** a hostile same-UID process is explicitly out of
scope. FROSTR-on-a-shared-multi-user-laptop is a separate threat model.

Hardening against a **different-UID, unprivileged** local attacker is the
target of this document. Every file and socket the shell touches is
restricted so a stranger on the same box cannot read profile secrets,
spoof the daemon, or hijack the control socket.

## Filesystem hardening

- `umask(0o077)` is set at the top of `main()` in the CLI binary. Any
  file or directory the shell process creates inherits a user-only
  default. The explicit `chmod` helpers below are belt-and-braces.
- Every secret-bearing file is written through
  `bifrost_profile::fs_guard::write_restricted_bytes_atomic(path, bytes, 0o600)`.
  That helper writes to a same-filesystem tempfile, `fsync`s it, sets
  perms on the tempfile **before** `persist`, then `fsync`s the parent
  directory. A crash mid-write leaves either the old file or the new
  file — never a partial write.
- Every profile-state directory is created through
  `bifrost_profile::fs_guard::ensure_dir_restricted(path, 0o700)`.
- The daemon log file is created with `OpenOptions::create(true).append(true)`
  and an explicit `chmod 0o600` immediately after open. Subsequent
  appends inherit the mode.
- `bfonboard` / `bfshare` / `bfprofile` export artifacts are written at
  `0o600` even though they are themselves encrypted. The package
  password is one factor; the file mode is the other.

## Daemon authentication

- The daemon token is a 256-bit random value drawn from `OsRng`,
  rendered as 64 lowercase hex chars. The previous predictable
  `daemon-<profile_id>-<unix_secs>` form is gone.
- The token is handed to the daemon child via `daemon.json` (`0o600`),
  not via argv. Nothing in `/proc/<pid>/cmdline` carries the secret.
- The daemon's control socket lives at:
  - `state_dir/profiles/<profile_id>/daemon.sock` when the path fits
    within the kernel `sun_path` limit;
  - otherwise `$XDG_RUNTIME_DIR/igloo-shell-<hash>.sock`, falling back to
    `/run/user/$UID/igloo-shell-<hash>.sock` on systemd hosts.
- If neither runtime-dir path is usable (macOS without `XDG_RUNTIME_DIR`,
  etc.), the shell surfaces a typed `TransportError::SocketPathTooLong`.
  **There is no `/tmp/` fallback.** Set `XDG_RUNTIME_DIR` to a shorter
  user-owned tmpfs path to recover.
- The socket file is chmod `0o600` immediately after `bind`. The parent
  directory is `0o700`.
- The daemon compares the inbound request token against the expected
  token in constant time via `subtle::ConstantTimeEq` (`DaemonToken`
  implements `PartialEq` over the subtle compare). The naive `!=`
  compare is gone.

## Passphrase transport

- The operator passphrase never lives on argv or in any env var the
  shell controls. Scripted invocations pipe it via stdin:

  ```bash
  echo "$PASSPHRASE" | igloo-shell profile load <id> --daemon
  echo "$PASSPHRASE" | igloo-shell daemon start --profile <id>
  ```

  Interactive callers see a hidden TTY prompt instead.
- When the shell spawns a daemon child, it writes the passphrase to the
  child's stdin and closes the pipe. The child's
  `bifrost_app::host::read_passphrase_from_stdin` helper reads one
  newline-terminated line, wraps it in a `bifrost_core::secret::Passphrase`,
  and drops the line buffer.
- `Passphrase`, `DaemonToken`, and the other 32-byte secret newtypes are
  `ZeroizeOnDrop` and have a redacted `Debug`. They do not derive
  `Clone`; any genuine fan-out call site uses an explicit `clone_secret()`
  call that an auditor can grep for.

## Argon2id / FileStoreKey

- The profile-encryption KDF is Argon2id with Bucket B defaults
  (`m=256 MiB`, `t=4`, `p=1`). Each derivation on a typical dev host
  takes ~400-600 ms.
- The daemon caches the derived `FileStoreKey` in an `UnlockSession` for
  the daemon's lifetime. Subsequent in-process decrypts (Wipe / Rotate /
  re-key) reuse the cached key instead of paying the Argon2 cost again.
- Passphrase rotation forces a daemon restart — the unlock session is
  not invalidated automatically. Share rotation is handled separately by
  the rotation flow (`rotate-key`, `rotate-keyset`).

## Rotation crash safety

- Rotation flows write `rotations/<workspace>/.intent.json` (`0o600`)
  before each step transition (`PreCreate`, `PostCreateNewProfile`,
  `PostWriteNewManifest`, `PreRemoveOldProfile`, `Completed`).
- On daemon startup the shell scans the rotations directory for
  incomplete intents and emits a `warn!` log line for each. Auto-recovery
  is intentionally **not** performed — the operator inspects the
  workspace manually and decides.
- A successful rotation deletes its intent file. Stale intent files are
  the canonical "needs attention" signal.

## What's out of scope

- Multi-user / hostile-same-UID threat model.
- Windows daemon mode (the daemon is `#[cfg(unix)]`-only).
- Per-operation re-authentication. The unlock session lives for the
  daemon's process lifetime.
- Automatic rollback of incomplete rotations (first pass detects only).

See `dev/plans/remediation-2026-04-22/bucket-c-secret-hygiene.md` in the
workspace root for the full design notes and the audit trail that led
to this contract.
