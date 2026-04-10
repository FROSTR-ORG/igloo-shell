use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow};
use bifrost_app::host::{
    DaemonClient, DaemonTransportConfig, EcdhPayload, OnboardPayload, PingPayload,
    RuntimeDiagnosticsSnapshot, ShutdownPayload, SignPayload, UpdatedPayload, WipedPayload,
};
use bifrost_app::native_runtime::DaemonMetadata;
use bifrost_core::types::PeerPolicyOverride;
use bifrost_signer::{
    DeviceConfig, PeerStatus, RuntimeMetadata, RuntimeReadiness, RuntimeStatusSummary,
};
use serde_json::Value;
use tokio::time::Duration;

use super::{
    PROFILE_PASSPHRASE_ENV, ProfileManifest, ShellPaths, load_share_payload,
    load_share_payload_with_passphrase, now_unix_secs, parse_group_package, parse_share_package,
    read_daemon_metadata, read_profile, read_relay_profile, remove_daemon_metadata,
    resolve_profile_peers_and_overrides, shorten_unix_socket_path, validate_profile_unlock,
    write_daemon_metadata,
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
    passphrase: Option<String>,
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
    Ok(DaemonClient::new(
        PathBuf::from(metadata.socket_path),
        metadata.token,
    ))
}

pub fn daemon_log_path(paths: &ShellPaths, profile_id: &str) -> PathBuf {
    paths.daemon_log_path(profile_id)
}

pub fn build_daemon_transport(profile: &ProfileManifest) -> DaemonTransportConfig {
    let socket_path = shorten_unix_socket_path(&profile.daemon_socket_path, &profile.id);
    DaemonTransportConfig {
        socket_path,
        token: format!("daemon-{}-{}", profile.id, now_unix_secs()),
    }
}

#[cfg(unix)]
pub async fn start_profile_daemon_with_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<DaemonMetadata> {
    paths.ensure()?;
    let profile = read_profile(paths, profile_id)?;
    validate_profile_unlock(paths, &profile, passphrase.clone())?;
    let transport = build_daemon_transport(&profile);
    let log_path = paths.daemon_log_path(profile_id);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let stderr = stdout.try_clone().context("clone daemon log handle")?;
    let exe = std::env::current_exe().context("resolve current executable")?;
    let mut command = Command::new(exe);
    command
        .arg("__daemon-run")
        .arg("--profile")
        .arg(profile_id)
        .arg("--socket-path")
        .arg(&transport.socket_path)
        .arg("--token")
        .arg(&transport.token)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(passphrase) = &passphrase {
        command.env(PROFILE_PASSPHRASE_ENV, passphrase);
    }
    let mut child = command.spawn().context("spawn igloo-shell daemon")?;

    let metadata = DaemonMetadata {
        profile_id: profile_id.to_string(),
        pid: child.id(),
        socket_path: transport.socket_path.display().to_string(),
        token: transport.token.clone(),
        log_path: log_path.display().to_string(),
        started_at: now_unix_secs(),
    };
    write_daemon_metadata(paths, profile_id, &metadata)?;

    let client = DaemonClient::new(PathBuf::from(&metadata.socket_path), metadata.token.clone());
    let mut last_error = None;
    for _ in 0..50 {
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
