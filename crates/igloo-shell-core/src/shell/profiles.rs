use std::fs;
use std::path::Path;

use bifrost_profile::{FilesystemProfileManifestStore, ProfileManifestStore};

use super::{
    DaemonMetadata, PolicyOverrideEntry, PolicyOverridesDocument, ProfileDoctorReport,
    ProfileManifest, RelayProfile, ShellPaths, decrypt_encrypted_profile, load_relay_profiles,
    load_shell_config, parse_policy_overrides_doc, read_encrypted_profile, read_json,
    remove_encrypted_profile, save_shell_config, write_json,
};
use anyhow::{Context, Result, anyhow, bail};
use bifrost_core::types::{PeerPolicyOverride, PolicyOverrideValue};

fn profile_store(paths: &ShellPaths) -> FilesystemProfileManifestStore {
    FilesystemProfileManifestStore::new(&paths.profiles_dir)
}

fn profile_domain(paths: &ShellPaths) -> bifrost_profile::FilesystemProfileDomain {
    bifrost_profile::FilesystemProfileDomain::new(
        &paths.config_path,
        &paths.relay_profiles_path,
        &paths.profiles_dir,
        &paths.groups_dir,
        &paths.encrypted_profiles_dir,
        &paths.state_profiles_dir,
    )
}

pub fn list_profiles(paths: &ShellPaths) -> Result<Vec<ProfileManifest>> {
    profile_store(paths).list_profiles()
}

pub fn read_profile(paths: &ShellPaths, profile_id: &str) -> Result<ProfileManifest> {
    profile_store(paths).read_profile(profile_id)
}

pub fn read_relay_profile(paths: &ShellPaths, relay_profile_id: &str) -> Result<RelayProfile> {
    load_relay_profiles(paths)?
        .into_iter()
        .find(|profile| profile.id == relay_profile_id)
        .ok_or_else(|| anyhow!("unknown relay profile {relay_profile_id}"))
}

pub fn write_profile(paths: &ShellPaths, profile: &ProfileManifest) -> Result<()> {
    profile_store(paths).write_profile(profile)
}

pub fn remove_profile(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    let profile = read_profile(paths, profile_id)?;
    profile_store(paths).remove_profile(profile_id)?;

    let state_dir = paths.profile_state_dir(profile_id);
    if state_dir.exists() {
        fs::remove_dir_all(&state_dir)
            .with_context(|| format!("remove {}", state_dir.display()))?;
    }

    if is_managed_group_path(paths, &profile.group_ref)
        && !is_group_ref_in_use(paths, &profile.id, &profile.group_ref)?
        && Path::new(&profile.group_ref).exists()
    {
        fs::remove_file(&profile.group_ref)
            .with_context(|| format!("remove {}", profile.group_ref))?;
    }

    if let Ok(record) = read_encrypted_profile(paths, &profile.encrypted_profile_ref)
        && !is_vault_ref_in_use(paths, &profile.id, &record.id)?
    {
        remove_encrypted_profile(paths, &record.id)?;
    }

    let mut config = load_shell_config(paths)?;
    if config.last_used_profile_id.as_deref() == Some(profile_id) {
        config.last_used_profile_id = None;
        save_shell_config(paths, &config)?;
    }
    Ok(())
}

pub fn read_daemon_metadata(paths: &ShellPaths, profile_id: &str) -> Result<DaemonMetadata> {
    let path = paths.daemon_metadata_path(profile_id);
    if !path.exists() {
        bail!("daemon metadata is not present for profile {profile_id}");
    }
    read_json(&path)
}

pub fn write_daemon_metadata(
    paths: &ShellPaths,
    profile_id: &str,
    metadata: &DaemonMetadata,
) -> Result<()> {
    write_json(&paths.daemon_metadata_path(profile_id), metadata)
}

pub fn remove_daemon_metadata(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    let path = paths.daemon_metadata_path(profile_id);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

pub fn doctor_profile(
    paths: &ShellPaths,
    profile: &ProfileManifest,
) -> Result<ProfileDoctorReport> {
    let relays = load_relay_profiles(paths)?;
    let relay_profile_exists = relays.iter().any(|entry| entry.id == profile.relay_profile);

    let mut missing_paths = Vec::new();
    let group_present = Path::new(&profile.group_ref).exists();
    if !group_present {
        missing_paths.push(profile.group_ref.clone());
    }

    let (share_managed, encrypted_profile_exists, vault_unlock_ok) =
        if let Ok(record) = read_encrypted_profile(paths, &profile.encrypted_profile_ref) {
            let ciphertext_exists = Path::new(&record.ciphertext_path).exists();
            if !ciphertext_exists {
                missing_paths.push(record.ciphertext_path.clone());
            }
            let unlock_ok =
                ciphertext_exists && decrypt_encrypted_profile(paths, &record, None).is_ok();
            (true, ciphertext_exists, unlock_ok)
        } else {
            let plaintext_exists = Path::new(&profile.encrypted_profile_ref).exists();
            if !plaintext_exists {
                missing_paths.push(profile.encrypted_profile_ref.clone());
            }
            (false, plaintext_exists, plaintext_exists)
        };

    let state_parent = Path::new(&profile.state_path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.profile_state_dir(&profile.id));
    if !state_parent.exists() {
        missing_paths.push(state_parent.display().to_string());
    }

    Ok(ProfileDoctorReport {
        profile_id: profile.id.clone(),
        ok: relay_profile_exists
            && group_present
            && encrypted_profile_exists
            && vault_unlock_ok
            && missing_paths.is_empty(),
        missing_paths,
        relay_profile_exists,
        group_present,
        share_managed,
        encrypted_profile_exists,
        vault_unlock_ok,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDirection {
    Request,
    Respond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMethod {
    Ping,
    Onboard,
    Sign,
    Ecdh,
}

fn policy_field_mut(
    policy: &mut PeerPolicyOverride,
    direction: PolicyDirection,
    method: PolicyMethod,
) -> &mut PolicyOverrideValue {
    let branch = match direction {
        PolicyDirection::Request => &mut policy.request,
        PolicyDirection::Respond => &mut policy.respond,
    };
    match method {
        PolicyMethod::Ping => &mut branch.ping,
        PolicyMethod::Onboard => &mut branch.onboard,
        PolicyMethod::Sign => &mut branch.sign,
        PolicyMethod::Ecdh => &mut branch.ecdh,
    }
}

fn merge_policy_override(
    base: &PeerPolicyOverride,
    next: &PeerPolicyOverride,
) -> PeerPolicyOverride {
    fn resolve(base: PolicyOverrideValue, next: PolicyOverrideValue) -> PolicyOverrideValue {
        match next {
            PolicyOverrideValue::Unset => base,
            other => other,
        }
    }

    PeerPolicyOverride {
        request: bifrost_core::types::MethodPolicyOverride {
            echo: resolve(base.request.echo, next.request.echo),
            ping: resolve(base.request.ping, next.request.ping),
            onboard: resolve(base.request.onboard, next.request.onboard),
            sign: resolve(base.request.sign, next.request.sign),
            ecdh: resolve(base.request.ecdh, next.request.ecdh),
        },
        respond: bifrost_core::types::MethodPolicyOverride {
            echo: resolve(base.respond.echo, next.respond.echo),
            ping: resolve(base.respond.ping, next.respond.ping),
            onboard: resolve(base.respond.onboard, next.respond.onboard),
            sign: resolve(base.respond.sign, next.respond.sign),
            ecdh: resolve(base.respond.ecdh, next.respond.ecdh),
        },
    }
}

fn is_empty_policy_override(policy: &PeerPolicyOverride) -> bool {
    let unset = PolicyOverrideValue::Unset;
    [
        policy.request.echo,
        policy.request.ping,
        policy.request.onboard,
        policy.request.sign,
        policy.request.ecdh,
        policy.respond.echo,
        policy.respond.ping,
        policy.respond.onboard,
        policy.respond.sign,
        policy.respond.ecdh,
    ]
    .into_iter()
    .all(|value| value == unset)
}

pub(crate) fn effective_policy_override(
    document: &PolicyOverridesDocument,
    peer_pubkey: &str,
) -> PeerPolicyOverride {
    let base = document.default_override.clone().unwrap_or_default();
    let specific = document
        .peer_overrides
        .iter()
        .find(|entry| entry.pubkey == peer_pubkey)
        .map(|entry| entry.policy_override.clone())
        .unwrap_or_default();
    merge_policy_override(&base, &specific)
}

pub fn set_profile_default_policy_override(
    paths: &ShellPaths,
    profile_id: &str,
    direction: PolicyDirection,
    method: PolicyMethod,
    value: PolicyOverrideValue,
) -> Result<ProfileManifest> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    let mut policy = document.default_override.clone().unwrap_or_default();
    *policy_field_mut(&mut policy, direction, method) = value;
    document.default_override = if is_empty_policy_override(&policy) {
        None
    } else {
        Some(policy)
    };
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok(profile)
}

pub fn set_profile_peer_policy_override(
    paths: &ShellPaths,
    profile_id: &str,
    peer_pubkey: &str,
    direction: PolicyDirection,
    method: PolicyMethod,
    value: PolicyOverrideValue,
) -> Result<(ProfileManifest, PeerPolicyOverride)> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    if let Some(existing) = document
        .peer_overrides
        .iter_mut()
        .find(|entry| entry.pubkey == peer_pubkey)
    {
        *policy_field_mut(&mut existing.policy_override, direction, method) = value;
    } else {
        let mut policy_override = PeerPolicyOverride::default();
        *policy_field_mut(&mut policy_override, direction, method) = value;
        document.peer_overrides.push(PolicyOverrideEntry {
            pubkey: peer_pubkey.to_string(),
            policy_override,
        });
    }
    document
        .peer_overrides
        .retain(|entry| !is_empty_policy_override(&entry.policy_override));
    document
        .peer_overrides
        .sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    let effective_override = effective_policy_override(&document, peer_pubkey);
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok((profile, effective_override))
}

pub fn clear_profile_peer_policy(
    paths: &ShellPaths,
    profile_id: &str,
    peer_pubkey: &str,
) -> Result<(ProfileManifest, PeerPolicyOverride)> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    document
        .peer_overrides
        .retain(|entry| entry.pubkey != peer_pubkey);
    let effective_policy = effective_policy_override(&document, peer_pubkey);
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok((profile, effective_policy))
}

pub(crate) fn touch_last_used_profile(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    profile_domain(paths).touch_last_used_profile(profile_id)
}

fn is_group_ref_in_use(
    paths: &ShellPaths,
    exclude_profile_id: &str,
    group_ref: &str,
) -> Result<bool> {
    Ok(list_profiles(paths)?
        .into_iter()
        .any(|profile| profile.id != exclude_profile_id && profile.group_ref == group_ref))
}

fn is_vault_ref_in_use(
    paths: &ShellPaths,
    exclude_profile_id: &str,
    encrypted_profile_id: &str,
) -> Result<bool> {
    Ok(list_profiles(paths)?.into_iter().any(|profile| {
        profile.id != exclude_profile_id && profile.encrypted_profile_ref == encrypted_profile_id
    }))
}

fn is_managed_group_path(paths: &ShellPaths, value: &str) -> bool {
    Path::new(value).starts_with(&paths.groups_dir)
}
