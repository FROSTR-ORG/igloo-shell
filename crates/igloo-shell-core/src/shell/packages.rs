use super::*;

pub(crate) fn profile_to_package_payload(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<&Passphrase>,
) -> Result<BfProfilePayload> {
    let profile = read_profile(paths, profile_id)?;
    let (manifest, resolved) =
        resolve_profile_runtime_for_passphrase(paths, profile_id, passphrase)?;
    let manual_peer_policy_overrides = resolved
        .manual_policy_overrides
        .iter()
        .map(|(pubkey, policy_override)| BfManualPeerPolicyOverride {
            pubkey: pubkey.clone(),
            policy: core_peer_policy_override_to_bf(policy_override),
        })
        .collect::<Vec<_>>();
    Ok(BfProfilePayload {
        profile_id: profile.id.clone(),
        version: 1,
        device: BfProfileDevice {
            name: manifest.label,
            share_secret: hex::encode(resolved.share.seckey.expose_bytes()),
            manual_peer_policy_overrides,
            relays: resolved.relays,
        },
        group_package: GroupPackageWire::from(resolved.group),
    })
}

pub(crate) fn group_from_payload(
    payload: &BfProfilePayload,
) -> Result<bifrost_core::types::GroupPackage> {
    bifrost_profile::group_from_payload(payload)
}

pub(crate) fn share_from_payload(
    group: &bifrost_core::types::GroupPackage,
    payload: &BfProfilePayload,
) -> Result<bifrost_core::types::SharePackage> {
    bifrost_profile::share_from_payload(group, payload)
}

pub(crate) fn rotation_payload_from_share(
    group: &bifrost_core::types::GroupPackage,
    share: &bifrost_core::types::SharePackage,
    label: String,
    relays: Vec<String>,
) -> Result<BfProfilePayload> {
    bifrost_profile::rotation_payload_from_share(group, share, label, relays)
}

pub(crate) async fn publish_profile_payload_backup(payload: &BfProfilePayload) -> Result<()> {
    let backup = create_encrypted_profile_backup(payload).context("build encrypted backup")?;
    let event = build_profile_backup_event(&payload.device.share_secret, &backup, None)
        .context("build backup event")?;
    publish_nostr_event(&payload.device.relays, &event).await
}

pub(crate) fn preview_from_bootstrap_completion(
    completion: &BootstrapImportResult,
    label: Option<String>,
    source: &'static str,
    peer_pubkey: Option<String>,
) -> Result<ProfilePreview> {
    let share_public_key = derive_member_pubkey_hex(*completion.share.seckey.expose_bytes())?;
    Ok(ProfilePreview {
        profile_id: derive_profile_id_for_share_secret(&hex::encode(
            completion.share.seckey.expose_bytes(),
        ))?,
        label: label.unwrap_or_else(|| format!("Onboarded Device {}", completion.share.idx)),
        share_public_key,
        group_public_key: hex::encode(completion.group.group_pk),
        threshold: completion.group.threshold as usize,
        total_count: completion.group.members.len(),
        relays: completion.relays.clone(),
        peer_pubkey,
        source,
    })
}

pub(crate) fn build_policy_overrides_value(
    policies: &[BfManualPeerPolicyOverride],
) -> Result<Value> {
    bifrost_profile::build_policy_overrides_value(policies)
}

pub(crate) fn write_package_output(out_path: Option<&Path>, package: &str) -> Result<()> {
    if let Some(path) = out_path {
        if let Some(parent) = path.parent() {
            // C.1/C.2: bfprofile / bfshare / bfonboard packages hold the
            // share's encrypted material plus the package-password KDF
            // params. The package is itself encrypted, but a 0o600 perm
            // bit on the on-disk artifact avoids accidental mode leakage
            // when the operator hands the file off to another host.
            #[cfg(unix)]
            bifrost_profile::fs_guard::ensure_dir_restricted(parent, 0o700)
                .with_context(|| format!("create {}", parent.display()))?;
            #[cfg(not(unix))]
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        #[cfg(unix)]
        bifrost_profile::fs_guard::write_restricted_bytes_atomic(path, package.as_bytes(), 0o600)
            .with_context(|| format!("write {}", path.display()))?;
        #[cfg(not(unix))]
        fs::write(path, package).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

pub(crate) fn rotation_workspace_manifest_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join("rotation.json")
}

pub(crate) fn hex_to_bytes32(value: &str) -> Result<[u8; 32]> {
    bifrost_profile::hex_to_bytes32(value)
}

pub(crate) fn find_member_index_for_share_secret(
    group: &bifrost_core::types::GroupPackage,
    share_secret: &str,
) -> Result<u16> {
    bifrost_profile::find_member_index_for_share_secret(group, share_secret)
}
