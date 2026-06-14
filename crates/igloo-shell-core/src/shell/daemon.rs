use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow};
use bifrost_app::host::{
    DaemonClient, DaemonTransportConfig, EcdhPayload, OnboardPayload, PingPayload,
    RuntimeDiagnosticsSnapshot, ShutdownPayload, SignPayload, UpdatedPayload, WipedPayload,
};
use bifrost_app::native_runtime::DaemonMetadata;
use bifrost_core::secret::{DaemonToken, Passphrase};
use bifrost_core::types::PeerPolicyOverride;
use bifrost_signer::{
    DeviceConfig, PeerStatus, RuntimeMetadata, RuntimeReadiness, RuntimeStatusSummary,
};
use rand_core::OsRng;
use serde_json::Value;
use tokio::time::Duration;

use super::{
    ProfileManifest, ShellPaths, load_share_payload, load_share_payload_with_passphrase,
    now_unix_secs, parse_group_package, parse_share_package, read_daemon_metadata, read_profile,
    read_relay_profile, remove_daemon_metadata, resolve_profile_peers_and_overrides,
    shorten_unix_socket_path, validate_profile_unlock, write_daemon_metadata,
};
use bifrost_app::runtime::{AppOptions, ResolvedAppConfig};

pub fn resolve_profile_runtime(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<(ProfileManifest, ResolvedAppConfig)> {
    let profile = read_profile(paths, profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;

    let group_raw = fs::read_to_string(&profile.group_ref)
        .with_context(|| format!("read {}", profile.group_ref))?;
    let share_raw = load_share_payload(paths, &profile)?;
    let group = parse_group_package(&group_raw).context("parse profile group package")?;
    let share = parse_share_package(&share_raw).context("parse profile share package")?;
    let (peers, manual_policy_overrides) =
        resolve_profile_peers_and_overrides(&group, &share, profile.policy_overrides.clone())
            .context("resolve peer policy overrides")?;
    let options: AppOptions = if profile.runtime_options.is_null() {
        AppOptions::default()
    } else {
        serde_json::from_value(profile.runtime_options.clone()).context("parse runtime options")?
    };

    Ok((
        profile.clone(),
        ResolvedAppConfig {
            group,
            share,
            state_path: PathBuf::from(&profile.state_path),
            relays: relay_profile.relays,
            peers,
            manual_policy_overrides,
            options,
        },
    ))
}

pub fn resolve_profile_runtime_for_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<&Passphrase>,
) -> Result<(ProfileManifest, ResolvedAppConfig)> {
    let profile = read_profile(paths, profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;
    let group_raw = fs::read_to_string(&profile.group_ref)
        .with_context(|| format!("read {}", profile.group_ref))?;
    let share_raw = load_share_payload_with_passphrase(paths, &profile, passphrase)?;
    let group = parse_group_package(&group_raw).context("parse profile group package")?;
    let share = parse_share_package(&share_raw).context("parse profile share package")?;
    let (peers, manual_policy_overrides) =
        resolve_profile_peers_and_overrides(&group, &share, profile.policy_overrides.clone())
            .context("resolve peer policy overrides")?;
    let options: AppOptions = if profile.runtime_options.is_null() {
        AppOptions::default()
    } else {
        serde_json::from_value(profile.runtime_options.clone()).context("parse runtime options")?
    };
    Ok((
        profile.clone(),
        ResolvedAppConfig {
            group,
            share,
            state_path: PathBuf::from(&profile.state_path),
            relays: relay_profile.relays,
            peers,
            manual_policy_overrides,
            options,
        },
    ))
}

#[cfg(unix)]
pub fn daemon_client(paths: &ShellPaths, profile_id: &str) -> Result<DaemonClient> {
    let metadata = read_daemon_metadata(paths, profile_id)?;
    let token = DaemonToken::from_hex(&metadata.token)
        .context("parse daemon.json token (run daemon stop && start to regenerate)")?;
    Ok(DaemonClient::new(
        PathBuf::from(metadata.socket_path),
        token,
    ))
}

pub fn daemon_log_path(paths: &ShellPaths, profile_id: &str) -> PathBuf {
    paths.daemon_log_path(profile_id)
}

/// Build a fresh `DaemonTransportConfig` for `profile`.
///
/// Bucket C C.4: the token is a 256-bit `OsRng`-derived `DaemonToken`. The
/// previous predictable `daemon-{id}-{ts}` form is gone.
pub fn build_daemon_transport(profile: &ProfileManifest) -> Result<DaemonTransportConfig> {
    let socket_path = shorten_unix_socket_path(&profile.daemon_socket_path, &profile.id)
        .map_err(|err| anyhow!(err))?;
    let mut rng = OsRng;
    Ok(DaemonTransportConfig {
        socket_path,
        token: DaemonToken::new_random(&mut rng),
    })
}

#[cfg(unix)]
pub async fn start_profile_daemon_with_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<Passphrase>,
) -> Result<DaemonMetadata> {
    paths.ensure()?;
    let profile = read_profile(paths, profile_id)?;
    // Validate the passphrase unlocks the profile before paying the daemon
    // spawn cost. `validate_profile_unlock` takes `Option<&Passphrase>`.
    validate_profile_unlock(paths, &profile, passphrase.as_ref())?;
    let transport = build_daemon_transport(&profile)?;
    let log_path = paths.daemon_log_path(profile_id);
    if let Some(parent) = log_path.parent() {
        // C.1: daemon log dir lives next to the daemon metadata; tighten to
        // 0o700 to match the surrounding profile state tree.
        bifrost_profile::fs_guard::ensure_dir_restricted(parent, 0o700)
            .with_context(|| format!("create {}", parent.display()))?;
    }

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    // C.1: the log file is open()-on-create, so chmod it explicitly. The
    // O_APPEND semantics rule out using `write_restricted_bytes_atomic`
    // here, so set 0o600 directly. Subsequent appends inherit the perms.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600));
    }
    let stderr = stdout.try_clone().context("clone daemon log handle")?;

    // C.4: write the daemon metadata (containing the expected token) BEFORE
    // spawning the child so it can read `daemon.json` keyed by `--profile`
    // and learn its expected token. The `--token` argv has been retired.
    let metadata_pre = DaemonMetadata {
        profile_id: profile_id.to_string(),
        // pid filled in after spawn — but we need the file present before
        // the child looks at it. Stash 0 as a placeholder; we overwrite the
        // record with the real pid once we know it.
        pid: 0,
        socket_path: transport.socket_path.display().to_string(),
        token: transport.token.to_hex(),
        log_path: log_path.display().to_string(),
        started_at: now_unix_secs(),
    };
    write_daemon_metadata(paths, profile_id, &metadata_pre)?;

    let exe = std::env::current_exe().context("resolve current executable")?;
    let mut command = Command::new(exe);
    command
        .arg("__daemon-run")
        .arg("--profile")
        .arg(profile_id)
        .arg("--socket-path")
        .arg(&transport.socket_path)
        // C.5: pipe the passphrase via stdin (closed after the write) — the
        // child's `read_passphrase_from_stdin` helper consumes one
        // newline-terminated line. No env-var passphrase contract.
        .stdin(Stdio::piped())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let mut child = command.spawn().context("spawn igloo-shell daemon")?;

    // Write the passphrase to the child's stdin and close the pipe.
    if let Some(mut child_stdin) = child.stdin.take() {
        if let Some(pass) = passphrase.as_ref() {
            child_stdin
                .write_all(pass.expose_bytes())
                .context("write passphrase to daemon stdin")?;
            child_stdin
                .write_all(b"\n")
                .context("write passphrase newline to daemon stdin")?;
        }
        // Dropping the handle closes the pipe (EOF for the child reader).
        drop(child_stdin);
    }
    // Passphrase is zeroized on drop here.
    drop(passphrase);

    let metadata = DaemonMetadata {
        profile_id: profile_id.to_string(),
        pid: child.id(),
        socket_path: transport.socket_path.display().to_string(),
        token: transport.token.to_hex(),
        log_path: log_path.display().to_string(),
        started_at: metadata_pre.started_at,
    };
    // Overwrite the placeholder with the real pid.
    write_daemon_metadata(paths, profile_id, &metadata)?;

    let client = DaemonClient::new(
        PathBuf::from(&metadata.socket_path),
        transport.token.clone_secret(),
    );
    // Bucket B Argon2id KDF runs once in the parent (validate_profile_unlock)
    // and once in the child (resolve_profile_runtime_with_unlock_session),
    // both with m=256MB / t=4. On contended hosts that easily stretches
    // past 5s. Poll for up to 30s (300 × 100ms) before giving up.
    let mut last_error = None;
    for _ in 0..300 {
        match client.runtime_metadata().await {
            Ok(_) => return Ok(metadata),
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if let Ok(None) = child.try_wait() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = remove_daemon_metadata(paths, profile_id);

    Err(anyhow!(
        "daemon did not become ready for profile {profile_id}: {}",
        last_error.unwrap_or_else(|| "unknown startup failure".to_string())
    ))
}

#[cfg(unix)]
pub async fn start_profile_daemon(paths: &ShellPaths, profile_id: &str) -> Result<DaemonMetadata> {
    start_profile_daemon_with_passphrase(paths, profile_id, None).await
}

#[cfg(unix)]
pub async fn stop_profile_daemon_typed(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<ShutdownPayload> {
    let client = daemon_client(paths, profile_id)?;
    let result = client.shutdown().await?;
    remove_daemon_metadata(paths, profile_id)?;
    Ok(result)
}

#[cfg(unix)]
pub async fn stop_profile_daemon(paths: &ShellPaths, profile_id: &str) -> Result<Value> {
    let result = stop_profile_daemon_typed(paths, profile_id).await?;
    serde_json::to_value(result).context("serialize daemon shutdown result")
}

#[cfg(unix)]
pub async fn daemon_runtime_status(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<RuntimeStatusSummary> {
    daemon_client(paths, profile_id)?.runtime_status().await
}

#[cfg(unix)]
pub async fn daemon_runtime_diagnostics(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<RuntimeDiagnosticsSnapshot> {
    daemon_client(paths, profile_id)?
        .runtime_diagnostics()
        .await
}

#[cfg(unix)]
pub async fn daemon_runtime_metadata(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<RuntimeMetadata> {
    daemon_client(paths, profile_id)?.runtime_metadata().await
}

#[cfg(unix)]
pub async fn daemon_runtime_readiness(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<RuntimeReadiness> {
    daemon_client(paths, profile_id)?.readiness().await
}

#[cfg(unix)]
pub async fn daemon_peer_status(paths: &ShellPaths, profile_id: &str) -> Result<Vec<PeerStatus>> {
    daemon_client(paths, profile_id)?.peer_status().await
}

#[cfg(unix)]
pub async fn daemon_runtime_config(paths: &ShellPaths, profile_id: &str) -> Result<DeviceConfig> {
    daemon_client(paths, profile_id)?.read_config().await
}

#[cfg(unix)]
pub async fn daemon_sign(
    paths: &ShellPaths,
    profile_id: &str,
    message_hex32: String,
) -> Result<SignPayload> {
    daemon_client(paths, profile_id)?
        .sign(message_hex32, None)
        .await
}

#[cfg(unix)]
pub async fn daemon_ecdh(
    paths: &ShellPaths,
    profile_id: &str,
    pubkey_hex32: String,
) -> Result<EcdhPayload> {
    daemon_client(paths, profile_id)?
        .ecdh(pubkey_hex32, None)
        .await
}

#[cfg(unix)]
pub async fn daemon_ping(
    paths: &ShellPaths,
    profile_id: &str,
    peer: String,
) -> Result<PingPayload> {
    daemon_client(paths, profile_id)?.ping(peer, None).await
}

#[cfg(unix)]
pub async fn daemon_onboard(
    paths: &ShellPaths,
    profile_id: &str,
    peer: String,
) -> Result<OnboardPayload> {
    daemon_client(paths, profile_id)?.onboard(peer, None).await
}

#[cfg(unix)]
pub async fn daemon_wipe_state(paths: &ShellPaths, profile_id: &str) -> Result<WipedPayload> {
    daemon_client(paths, profile_id)?.wipe_state().await
}

#[cfg(unix)]
pub async fn daemon_set_policy_override(
    paths: &ShellPaths,
    profile_id: &str,
    peer: String,
    policy_override: &PeerPolicyOverride,
) -> Result<UpdatedPayload> {
    daemon_client(paths, profile_id)?
        .set_policy_override(peer, policy_override)
        .await
}

#[cfg(unix)]
pub async fn daemon_clear_peer_policy_overrides(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<UpdatedPayload> {
    daemon_client(paths, profile_id)?
        .clear_peer_policy_overrides()
        .await
}

#[cfg(unix)]
pub async fn daemon_resolve_approval(
    paths: &ShellPaths,
    profile_id: &str,
    request_id: String,
    approved: bool,
) -> Result<UpdatedPayload> {
    daemon_client(paths, profile_id)?
        .resolve_approval(request_id, approved)
        .await
}
