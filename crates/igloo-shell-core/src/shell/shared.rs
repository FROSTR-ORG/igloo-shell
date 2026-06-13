use super::*;
use bifrost_profile::FilesystemProfileDomain;
use thiserror::Error;

fn profile_domain(paths: &ShellPaths) -> FilesystemProfileDomain {
    FilesystemProfileDomain::new(
        &paths.config_path,
        &paths.relay_profiles_path,
        &paths.profiles_dir,
        &paths.groups_dir,
        &paths.encrypted_profiles_dir,
        &paths.state_profiles_dir,
    )
}

pub(crate) fn ensure_onboarding_relay_profile(
    paths: &ShellPaths,
    requested: Option<String>,
    label: Option<&str>,
    relays: &[String],
) -> Result<String> {
    profile_domain(paths).ensure_onboarding_relay_profile(requested, label, relays, now_unix_secs())
}

pub(crate) fn store_group_package(
    paths: &ShellPaths,
    group: &bifrost_core::types::GroupPackage,
) -> Result<String> {
    profile_domain(paths).store_group_package(group)
}

pub(crate) fn build_profile_manifest(
    paths: &ShellPaths,
    profile_id: &str,
    label: String,
    group_ref: String,
    encrypted_profile_ref: String,
    relay_profile: String,
    created_at: u64,
) -> ProfileManifest {
    let state_dir = paths.profile_state_dir(profile_id);
    bifrost_profile::build_profile_manifest(
        profile_id,
        label,
        group_ref,
        encrypted_profile_ref,
        relay_profile,
        state_dir.join("signer-state.bin").display().to_string(),
        state_dir.join("daemon.sock").display().to_string(),
        created_at,
    )
}

pub(crate) fn parse_policy_overrides_doc(value: Value) -> Result<PolicyOverridesDocument> {
    bifrost_profile::parse_policy_overrides_doc(value)
}

pub(crate) fn resolve_profile_peers_and_overrides(
    group: &bifrost_core::types::GroupPackage,
    share: &bifrost_core::types::SharePackage,
    value: Value,
) -> Result<(Vec<String>, HashMap<String, PeerPolicyOverride>)> {
    let document = parse_policy_overrides_doc(value)?;
    let local_pubkey = derive_member_pubkey_hex(*share.seckey.expose_bytes())?;
    let peer_keys = group
        .members
        .iter()
        .map(|member| hex::encode(&member.pubkey[1..]))
        .filter(|pubkey| pubkey != &local_pubkey)
        .collect::<Vec<_>>();

    let mut peers = Vec::with_capacity(peer_keys.len());
    let mut manual_policy_overrides = HashMap::new();
    for pubkey in peer_keys {
        let effective_override = effective_policy_override(&document, &pubkey);
        manual_policy_overrides.insert(pubkey.clone(), effective_override);
        peers.push(pubkey);
    }
    peers.sort();
    Ok((peers, manual_policy_overrides))
}

pub(crate) fn derive_member_pubkey_hex(seckey: [u8; 32]) -> Result<String> {
    bifrost_profile::derive_member_pubkey_hex(seckey)
}

pub(crate) fn derive_profile_id_for_share_secret(share_secret_hex: &str) -> Result<String> {
    bifrost_profile::derive_profile_id_for_share_secret(share_secret_hex)
}

/// Errors raised when computing a Unix-domain socket path for the daemon.
///
/// Bucket C C.4: the long-path fallback used to land in `/tmp/`, which is
/// world-writable on every common Unix. The new flow tries
/// `XDG_RUNTIME_DIR` (typically `/run/user/$UID`, tmpfs, 0o700 by default
/// on systemd hosts) and surfaces this typed error if neither the original
/// path nor a runtime-dir fallback is usable. There is no `/tmp` fallback.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The configured socket path exceeds the host's sun_path limit and no
    /// suitable runtime-dir override is available.
    #[error(
        "unix socket path is too long ({path:?}, limit {limit} bytes); set XDG_RUNTIME_DIR to a directory shorter than the limit"
    )]
    SocketPathTooLong { path: String, limit: usize },
}

/// Resolve a daemon-socket path within the Unix `sun_path` length limit by
/// delegating to the canonical secure shortener in `bifrost_app`
/// (`XDG_RUNTIME_DIR` → `/run/user/$UID` → a 0o700 `~/.igloo-shell/run`
/// fallback; never `/tmp`, per Bucket C C.4). Surfaces a typed error only in
/// the degenerate case where the result still exceeds the budget (e.g. `HOME`
/// unset on a host without any runtime dir).
pub(crate) fn shorten_unix_socket_path(
    raw_path: &str,
    profile_id: &str,
) -> Result<PathBuf, TransportError> {
    let path = bifrost_app::native_runtime::shorten_unix_socket_path(raw_path, profile_id);
    #[cfg(unix)]
    if path.as_os_str().to_string_lossy().len() >= bifrost_app::native_runtime::SUN_PATH_BUDGET {
        return Err(TransportError::SocketPathTooLong {
            path: raw_path.to_string(),
            limit: bifrost_app::native_runtime::SUN_PATH_BUDGET,
        });
    }
    Ok(path)
}
