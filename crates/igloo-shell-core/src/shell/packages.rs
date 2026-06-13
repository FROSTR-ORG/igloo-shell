use super::*;
use nostr::ToBech32;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Recovered group secret-key material. The signing key is reconstructed from a
/// threshold of shares and never persisted by this crate; the caller decides
/// how to surface it (the shell CLI writes the `nsec` to a `0o600` file). The
/// secret fields are zeroized on drop and redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveredGroupKey {
    pub nsec: String,
    pub signing_key_hex: String,
    #[zeroize(skip)]
    pub group_public_key: String,
}

impl std::fmt::Debug for RecoveredGroupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredGroupKey")
            .field("nsec", &"<redacted>")
            .field("signing_key_hex", &"<redacted>")
            .field("group_public_key", &self.group_public_key)
            .finish()
    }
}

/// Reconstruct the group secret key (nsec) from a threshold of shares, fully
/// local — no relay. The recovering device's own `profile_id` supplies both the
/// group package (member indices) and its own share (unlocked with `passphrase`);
/// the operator pastes the remaining `threshold - 1` members' `bfshare` packages
/// as `(package_text, package_secret)` pairs. Each pasted share secret is mapped
/// to its member index via the local group package and **fails loudly** if it is
/// not a member of this group (mirrors the browser `shareWireFromSecret`).
pub fn recover_group_secret_from_profile_and_shares(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<&Passphrase>,
    pasted: &[(String, String)],
) -> Result<RecoveredGroupKey> {
    let payload = profile_to_package_payload(paths, profile_id, passphrase)?;
    let group = group_from_payload(&payload)?;

    // The local device contributes its own share first.
    let device_share = share_from_payload(&group, &payload)?;
    let mut seen_idx = HashSet::new();
    seen_idx.insert(device_share.idx);
    let mut shares = vec![device_share];

    for (package_text, package_secret) in pasted {
        let decoded = decode_bfshare_package(package_text, package_secret)
            .map_err(|error| anyhow!("decode pasted bfshare package: {error}"))?;
        let idx = find_member_index_for_share_secret(&group, &decoded.share_secret)
            .context("pasted bfshare does not belong to this profile's group")?;
        if !seen_idx.insert(idx) {
            bail!(
                "member {idx} was supplied more than once (the local profile already \
                 contributes its own share; paste only the other members' bfshares)"
            );
        }
        shares.push(bifrost_core::types::SharePackage {
            idx,
            seckey: bifrost_core::secret::SharePrivateKey::new(hex_to_bytes32(
                &decoded.share_secret,
            )?),
        });
    }

    if shares.len() < group.threshold as usize {
        bail!(
            "insufficient shares to recover the group key: need {} (have {})",
            group.threshold,
            shares.len()
        );
    }

    let recovered = recover_key(&RecoverKeyInput {
        group: group.clone(),
        shares,
    })
    .map_err(|error| anyhow!("recover group secret key: {error}"))?;
    let signing_key32 = recovered.signing_key32.expose_bytes();
    let secret_key =
        nostr::SecretKey::from_slice(signing_key32).context("parse recovered group secret key")?;
    Ok(RecoveredGroupKey {
        nsec: secret_key.to_bech32().context("encode recovered nsec")?,
        signing_key_hex: hex::encode(signing_key32),
        group_public_key: hex::encode(group.group_pk),
    })
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
