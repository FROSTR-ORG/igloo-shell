use super::*;
use bifrost_profile::{preview_bfshare_recovery, publish_profile_backup};

pub fn finalize_rotation_update_import(
    paths: &ShellPaths,
    target: &ProfileManifest,
    target_payload: BfProfilePayload,
    rotated_group: &bifrost_core::types::GroupPackage,
    rotated_payload: BfProfilePayload,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    if hex::encode(rotated_group.group_pk)
        != hex::encode(group_from_payload(&target_payload)?.group_pk)
    {
        bail!("rotation update does not match the selected profile group public key");
    }
    if rotated_payload.profile_id == target_payload.profile_id {
        bail!("rotation update did not produce a new device profile id");
    }

    paths.ensure()?;
    let share = bifrost_core::types::SharePackage {
        idx: find_member_index_for_share_secret(
            rotated_group,
            &rotated_payload.device.share_secret,
        )?,
        seckey: hex_to_bytes32(&rotated_payload.device.share_secret)?,
    };
    let relay_profile_id = ensure_onboarding_relay_profile(
        paths,
        Some(target.relay_profile.clone()),
        Some(target.label.as_str()),
        &rotated_payload.device.relays,
    )?;
    let now = now_unix_secs();
    let group_ref = store_group_package(paths, rotated_group)?;
    let share_raw = serde_json::to_string_pretty(&SharePackageWire::from(share.clone()))
        .context("serialize rotated share package")?;
    let encrypted_profile = store_encrypted_profile(
        paths,
        "share_package",
        "rotation_update",
        &share_raw,
        passphrase,
    )?;
    let mut migrated = build_profile_manifest(
        paths,
        &rotated_payload.profile_id,
        target.label.clone(),
        group_ref,
        encrypted_profile.id.clone(),
        relay_profile_id,
        now,
    );
    migrated.policy_overrides =
        build_policy_overrides_value(&rotated_payload.device.manual_peer_policy_overrides)?;
    migrated.runtime_options = target.runtime_options.clone();
    migrated.last_used_at = target.last_used_at;
    fs::create_dir_all(paths.profile_state_dir(&migrated.id))
        .with_context(|| format!("create {}", paths.profile_state_dir(&migrated.id).display()))?;
    write_profile(paths, &migrated)?;

    remove_profile(paths, &target.id)?;
    touch_last_used_profile(paths, &migrated.id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile: migrated,
        encrypted_profile,
        diagnostics: None,
        warnings: Vec::new(),
    })
}

pub async fn apply_rotation_update_from_bfonboard_value(
    paths: &ShellPaths,
    target_profile_id: &str,
    package_raw: &str,
    onboarding_password: String,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    let target = read_profile(paths, target_profile_id)?;
    let target_payload = profile_to_package_payload(paths, target_profile_id, passphrase.clone())?;
    let connection = connect_onboarding_package_preview(package_raw, onboarding_password).await?;

    if connection.preview.group_public_key
        != hex::encode(group_from_payload(&target_payload)?.group_pk)
    {
        bail!("rotation update does not match the selected profile group public key");
    }
    if connection.preview.profile_id == target_payload.profile_id {
        bail!("rotation update did not produce a new device profile id");
    }

    let rotated_payload = BfProfilePayload {
        profile_id: connection.preview.profile_id.clone(),
        version: 1,
        device: BfProfileDevice {
            name: target.label.clone(),
            share_secret: hex::encode(connection.completion.share.seckey),
            manual_peer_policy_overrides: Vec::new(),
            relays: connection.completion.relays.clone(),
        },
        group_package: GroupPackageWire::from(connection.completion.group.clone()),
    };

    finalize_rotation_update_import(
        paths,
        &target,
        target_payload,
        &connection.completion.group,
        rotated_payload,
        passphrase,
    )
}

pub fn default_rotation_workspace_path(paths: &ShellPaths, source_profile_id: &str) -> PathBuf {
    paths
        .rotations_dir
        .join(format!("{}-{}", source_profile_id, now_unix_secs()))
}

pub fn create_rotation_workspace(
    paths: &ShellPaths,
    source_profile_id: &str,
    threshold: u16,
    count: u16,
    workspace_root: &Path,
    source_package_paths: Vec<String>,
    passphrase: Option<String>,
) -> Result<RotationWorkspaceDocument> {
    paths.ensure()?;
    let source_profile = read_profile(paths, source_profile_id)?;
    let source_payload = profile_to_package_payload(paths, source_profile_id, passphrase)?;
    create_keyset(CreateKeysetConfig {
        group_name: source_payload.group_package.group_name.clone(),
        threshold,
        count,
        signing_key32: None,
    })
    .map_err(|error| anyhow!("validate rotation geometry: {error}"))?;
    let source_group = group_from_payload(&source_payload)?;
    let source_share = share_from_payload(&source_group, &source_payload)?;
    let source_group_id =
        hex::encode(get_group_id(&source_group).context("derive source group id")?);
    let source_group_name = source_payload.group_package.group_name.clone();

    if workspace_root.exists() {
        bail!(
            "rotation workspace already exists at {}",
            workspace_root.display()
        );
    }

    let targets = (1..=count)
        .map(|member_index| RotationWorkspaceTarget {
            member_index,
            mode: if member_index == source_share.idx {
                RotationTargetMode::LocalReplace
            } else {
                RotationTargetMode::Bfonboard
            },
            label: if member_index == source_share.idx {
                source_profile.label.clone()
            } else {
                format!("{source_group_name} Device {member_index}")
            },
            relays: source_payload.device.relays.clone(),
            usage_hint: if member_index == source_share.idx {
                None
            } else {
                Some(RotationUsageHint::RotateExistingDevice)
            },
            replace_profile_id: if member_index == source_share.idx {
                Some(source_profile_id.to_string())
            } else {
                None
            },
            output_path: if member_index == source_share.idx {
                None
            } else {
                Some(
                    workspace_root
                        .join("packages")
                        .join(format!("member-{member_index}.bfonboard.txt"))
                        .display()
                        .to_string(),
                )
            },
        })
        .collect::<Vec<_>>();

    let document = RotationWorkspaceDocument {
        version: 1,
        source_profile_id: source_profile_id.to_string(),
        source_group_id,
        source_group_public_key: hex::encode(source_group.group_pk),
        source_group_name,
        source_threshold: source_group.threshold,
        source_count: source_group.members.len() as u16,
        next_threshold: threshold,
        next_count: count,
        source_packages: source_package_paths
            .into_iter()
            .map(|package_path| RotationWorkspaceSource {
                package_path,
                package_secret_env: None,
                package_secret_file: None,
            })
            .collect(),
        targets,
    };
    write_rotation_workspace(workspace_root, &document)?;
    Ok(document)
}

pub fn load_rotation_workspace(workspace_root: &Path) -> Result<RotationWorkspaceDocument> {
    read_json(&rotation_workspace_manifest_path(workspace_root))
}

pub fn write_rotation_workspace(
    workspace_root: &Path,
    document: &RotationWorkspaceDocument,
) -> Result<()> {
    fs::create_dir_all(workspace_root)
        .with_context(|| format!("create {}", workspace_root.display()))?;
    fs::create_dir_all(workspace_root.join("packages"))
        .with_context(|| format!("create {}", workspace_root.join("packages").display()))?;
    write_json(&rotation_workspace_manifest_path(workspace_root), document)
}

pub fn inspect_rotation_workspace(
    workspace_root: &Path,
    document: &RotationWorkspaceDocument,
) -> RotationWorkspaceStatus {
    let mut validation_errors = Vec::new();
    let mut missing_secret_entries = Vec::new();
    let mut seen_members = HashSet::new();
    let mut local_target_member_index = None;
    let mut local_replace_profile_id = None;
    let mut local_target_count = 0usize;
    let mut remote_target_count = 0usize;

    if document.version != 1 {
        validation_errors.push(format!(
            "unsupported rotation workspace version {}; expected 1",
            document.version
        ));
    }
    if document.next_threshold == 0 || document.next_threshold > document.next_count {
        validation_errors.push("rotation threshold/count is invalid".to_string());
    }
    if document.targets.len() != document.next_count as usize {
        validation_errors.push(format!(
            "rotation workspace must contain exactly {} target entries",
            document.next_count
        ));
    }
    for source in &document.source_packages {
        if source.package_secret_env.is_none() && source.package_secret_file.is_none() {
            missing_secret_entries.push(source.package_path.clone());
        }
    }
    for target in &document.targets {
        if !seen_members.insert(target.member_index) {
            validation_errors.push(format!(
                "member {} is assigned more than once",
                target.member_index
            ));
        }
        if target.member_index == 0 || target.member_index > document.next_count {
            validation_errors.push(format!(
                "member {} is outside the configured rotated count {}",
                target.member_index, document.next_count
            ));
        }
        if target.label.trim().is_empty() {
            validation_errors.push(format!("member {} is missing a label", target.member_index));
        }
        if target.relays.is_empty() {
            validation_errors.push(format!(
                "member {} must have at least one relay",
                target.member_index
            ));
        }
        match target.mode {
            RotationTargetMode::LocalReplace => {
                local_target_count += 1;
                local_target_member_index = Some(target.member_index);
                local_replace_profile_id = target.replace_profile_id.clone();
                if target
                    .replace_profile_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    validation_errors.push(format!(
                        "member {} must declare replace_profile_id for local_replace",
                        target.member_index
                    ));
                }
                if target.usage_hint.is_some() {
                    validation_errors.push(format!(
                        "member {} must not set usage_hint for local_replace",
                        target.member_index
                    ));
                }
            }
            RotationTargetMode::Bfonboard => {
                remote_target_count += 1;
                if target.usage_hint.is_none() {
                    validation_errors.push(format!(
                        "member {} must declare usage_hint for bfonboard output",
                        target.member_index
                    ));
                }
            }
        }
    }
    if local_target_count != 1 {
        validation_errors
            .push("rotation workspace must contain exactly one local_replace target".to_string());
    }

    RotationWorkspaceStatus {
        workspace_path: workspace_root.display().to_string(),
        ready: validation_errors.is_empty()
            && missing_secret_entries.is_empty()
            && document.source_packages.len() >= document.source_threshold as usize,
        source_profile_id: document.source_profile_id.clone(),
        source_group_id: document.source_group_id.clone(),
        source_group_public_key: document.source_group_public_key.clone(),
        source_threshold: document.source_threshold,
        next_threshold: document.next_threshold,
        next_count: document.next_count,
        source_packages_present: document.source_packages.len(),
        source_packages_required: document.source_threshold as usize,
        local_target_member_index,
        local_replace_profile_id,
        remote_target_count,
        missing_secret_entries,
        validation_errors,
    }
}

pub async fn generate_rotation_workspace(
    paths: &ShellPaths,
    workspace_root: &Path,
    source_passwords: Vec<String>,
    passphrase: Option<String>,
    distribution_password: Option<String>,
) -> Result<RotationGenerateResult> {
    let document = load_rotation_workspace(workspace_root)?;
    let status = inspect_rotation_workspace(workspace_root, &document);
    if !status.validation_errors.is_empty() {
        bail!(
            "rotation workspace is invalid: {}",
            status.validation_errors.join("; ")
        );
    }
    if document.source_packages.len() < document.source_threshold as usize {
        bail!(
            "rotation requires at least {} source packages",
            document.source_threshold
        );
    }
    if source_passwords.len() != document.source_packages.len() {
        bail!(
            "rotation source password count {} does not match source package count {}",
            source_passwords.len(),
            document.source_packages.len()
        );
    }

    let mut recovered = Vec::new();
    for (index, source) in document.source_packages.iter().enumerate() {
        let package_raw = fs::read_to_string(&source.package_path)
            .with_context(|| format!("read {}", source.package_path))?;
        let (_, payload) =
            preview_bfshare_recovery(&package_raw, source_passwords[index].clone(), None)
                .await
                .with_context(|| format!("recover {}", source.package_path))?;
        recovered.push(payload);
    }
    let current_group = group_from_payload(&recovered[0])?;
    let current_group_id =
        hex::encode(get_group_id(&current_group).context("derive current group id")?);
    let current_group_pk = hex::encode(current_group.group_pk);
    if current_group_id != document.source_group_id {
        bail!("rotation sources do not match the workspace source group id");
    }
    if current_group_pk != document.source_group_public_key {
        bail!("rotation sources do not match the workspace group public key");
    }
    for payload in recovered.iter().skip(1) {
        let candidate = group_from_payload(payload)?;
        if hex::encode(candidate.group_pk) != current_group_pk {
            bail!("rotation sources do not share the same group public key");
        }
        if hex::encode(get_group_id(&candidate)?) != current_group_id {
            bail!("rotation sources do not belong to the same current group configuration");
        }
    }

    let shares = recovered
        .iter()
        .map(|payload| share_from_payload(&current_group, payload))
        .collect::<Result<Vec<_>>>()?;

    let rotated = rotate_keyset_dealer(
        &current_group,
        RotateKeysetRequest {
            shares,
            threshold: document.next_threshold,
            count: document.next_count,
        },
    )
    .map_err(|error| anyhow!("rotate keyset: {error}"))?;

    let local_target = document
        .targets
        .iter()
        .find(|target| target.mode == RotationTargetMode::LocalReplace)
        .ok_or_else(|| anyhow!("rotation workspace is missing a local_replace target"))?;
    let local_share = rotated
        .next
        .shares
        .iter()
        .find(|share| share.idx == local_target.member_index)
        .ok_or_else(|| anyhow!("rotated share {} not found", local_target.member_index))?;
    let replace_profile_id = local_target
        .replace_profile_id
        .clone()
        .ok_or_else(|| anyhow!("local_replace target is missing replace_profile_id"))?;
    let target = read_profile(paths, &replace_profile_id)?;
    let target_payload =
        profile_to_package_payload(paths, &replace_profile_id, passphrase.clone())?;
    let local_payload = rotation_payload_from_share(
        &rotated.next.group,
        local_share,
        local_target.label.clone(),
        local_target.relays.clone(),
    )?;
    let import = finalize_rotation_update_import(
        paths,
        &target,
        target_payload,
        &rotated.next.group,
        local_payload,
        passphrase.clone(),
    )?;
    let profile = match import {
        ProfileImportResult::ProfileCreated { profile, .. } => profile,
        _ => bail!("rotation did not produce a local profile"),
    };
    publish_profile_backup(paths, &profile.id, passphrase.clone()).await?;

    let remote_targets = document
        .targets
        .iter()
        .filter(|target| target.mode == RotationTargetMode::Bfonboard)
        .collect::<Vec<_>>();
    let distribution_password = if remote_targets.is_empty() {
        None
    } else {
        Some(distribution_password.ok_or_else(|| {
            anyhow!("rotation requires a distribution secret to emit bfonboard packages")
        })?)
    };

    let packages_dir = workspace_root.join("packages");
    fs::create_dir_all(&packages_dir)
        .with_context(|| format!("create {}", packages_dir.display()))?;
    let mut generated_packages = Vec::new();
    for target in remote_targets {
        let share = rotated
            .next
            .shares
            .iter()
            .find(|share| share.idx == target.member_index)
            .ok_or_else(|| anyhow!("rotated share {} not found", target.member_index))?;
        let payload = rotation_payload_from_share(
            &rotated.next.group,
            share,
            target.label.clone(),
            target.relays.clone(),
        )?;
        publish_profile_payload_backup(&payload).await?;
        let output_path = target
            .output_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                packages_dir.join(format!("member-{}.bfonboard.txt", target.member_index))
            });
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let package = export_rotated_onboarding_package(
            &rotated.next.group,
            local_share,
            share,
            target.relays.clone(),
            distribution_password
                .as_ref()
                .expect("distribution password should exist when remote targets exist")
                .clone(),
        )?;
        write_package_output(Some(&output_path), &package)?;
        generated_packages.push(RotationGeneratedPackage {
            member_index: target.member_index,
            label: target.label.clone(),
            profile_id: payload.profile_id,
            usage_hint: target.usage_hint.ok_or_else(|| {
                anyhow!(
                    "rotation target {} is missing usage_hint",
                    target.member_index
                )
            })?,
            path: output_path.display().to_string(),
        });
    }

    Ok(RotationGenerateResult {
        workspace_path: workspace_root.display().to_string(),
        source_group_id: document.source_group_id,
        next_group_id: hex::encode(rotated.next_group_id),
        replaced_profile_id: replace_profile_id,
        profile,
        generated_packages,
    })
}

pub fn create_generated_keyset_draft(
    group_name: String,
    threshold: u16,
    count: u16,
) -> Result<GeneratedKeysetDraft> {
    let bundle = create_keyset(CreateKeysetConfig {
        group_name: group_name.clone(),
        threshold,
        count,
        signing_key32: None,
    })
    .map_err(|error| anyhow!("create keyset: {error}"))?;
    let shares = bundle
        .shares
        .iter()
        .map(|share| {
            Ok(GeneratedShareDraft {
                member_idx: share.idx,
                label: format!("{group_name} Device {}", share.idx),
                share_public_key: derive_member_pubkey_hex(share.seckey)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(GeneratedKeysetDraft {
        group_name,
        threshold,
        count,
        group_public_key: hex::encode(bundle.group.group_pk),
        shares,
        group: bundle.group,
        share_packages: bundle.shares,
    })
}

pub fn import_generated_share(
    paths: &ShellPaths,
    draft: &GeneratedKeysetDraft,
    member_idx: u16,
    label: String,
    relay_urls: Vec<String>,
    passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    if relay_urls.is_empty() {
        bail!("at least one relay is required");
    }
    let Some(share) = draft
        .share_packages
        .iter()
        .find(|share| share.idx == member_idx)
    else {
        bail!("generated share {member_idx} not found");
    };
    let local_pubkey = derive_member_pubkey_hex(share.seckey)?;
    let share_secret_hex = hex::encode(share.seckey);
    let payload = BfProfilePayload {
        profile_id: derive_profile_id_for_share_secret(&share_secret_hex)?,
        version: 1,
        device: BfProfileDevice {
            name: label.clone(),
            share_secret: share_secret_hex,
            manual_peer_policy_overrides: draft
                .group
                .members
                .iter()
                .map(|member| hex::encode(&member.pubkey[1..]))
                .filter(|pubkey| pubkey != &local_pubkey)
                .map(|pubkey| BfManualPeerPolicyOverride {
                    pubkey,
                    policy: core_peer_policy_override_to_bf(&PeerPolicyOverride::from_peer_policy(
                        &PeerPolicy::default(),
                    )),
                })
                .collect(),
            relays: relay_urls,
        },
        group_package: GroupPackageWire::from(draft.group.clone()),
    };
    import_profile_from_bfprofile_payload(paths, payload, Some(label), None, passphrase)
}

pub fn export_generated_onboarding_package(
    draft: &GeneratedKeysetDraft,
    member_idx: u16,
    relays: Vec<String>,
    peer_pubkey: String,
    package_password: String,
) -> Result<String> {
    if relays.is_empty() {
        bail!("at least one relay is required");
    }
    let Some(share) = draft
        .share_packages
        .iter()
        .find(|share| share.idx == member_idx)
    else {
        bail!("generated share {member_idx} not found");
    };
    encode_bfonboard_package(
        &BfOnboardPayload {
            share_secret: hex::encode(share.seckey),
            relays,
            peer_pk: peer_pubkey,
        },
        &package_password,
    )
    .context("encode bfonboard package")
}

fn export_rotated_onboarding_package(
    group: &bifrost_core::types::GroupPackage,
    local_share: &bifrost_core::types::SharePackage,
    target_share: &bifrost_core::types::SharePackage,
    relays: Vec<String>,
    package_password: String,
) -> Result<String> {
    if relays.is_empty() {
        bail!("at least one relay is required");
    }
    if local_share.idx == target_share.idx {
        bail!("rotation onboarding target must differ from the local replacement member");
    }
    if !group
        .members
        .iter()
        .any(|member| member.idx == local_share.idx)
    {
        bail!("rotated group is missing the local replacement member");
    }
    if !group
        .members
        .iter()
        .any(|member| member.idx == target_share.idx)
    {
        bail!("rotated group is missing the target member");
    }
    encode_bfonboard_package(
        &BfOnboardPayload {
            share_secret: hex::encode(target_share.seckey),
            relays,
            peer_pk: derive_member_pubkey_hex(local_share.seckey)?,
        },
        &package_password,
    )
    .context("encode rotated bfonboard package")
}
