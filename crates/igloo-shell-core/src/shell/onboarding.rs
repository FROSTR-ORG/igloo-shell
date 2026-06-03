use super::*;
use bifrost_app::native_runtime::ConnectedOnboardingImport;
use bifrost_profile::FilesystemProfileDomain;

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

pub fn import_profile_from_files(
    paths: &ShellPaths,
    group_path: &Path,
    share_path: &Path,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<Passphrase>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let group_raw =
        fs::read_to_string(group_path).with_context(|| format!("read {}", group_path.display()))?;
    let share_raw =
        fs::read_to_string(share_path).with_context(|| format!("read {}", share_path.display()))?;
    let group = parse_group_package(&group_raw).context("parse group package")?;
    let share = parse_share_package(&share_raw).context("parse share package")?;
    // C.5: env-var fallback removed; callers must supply Passphrase explicitly.
    let passphrase = passphrase.ok_or_else(|| anyhow!("passphrase not provided"))?;
    let now = now_unix_secs();
    let imported = profile_domain(paths).import_profile_from_files(
        &group,
        &share,
        &share_raw,
        label,
        relay_profile,
        passphrase.expose_secret(),
        now,
    )?;

    Ok(ProfileImportResult::ProfileCreated {
        profile: imported.profile,
        encrypted_profile: imported.encrypted_profile,
        diagnostics: None,
        warnings: Vec::new(),
    })
}

pub fn stage_onboarding_import(
    paths: &ShellPaths,
    package_path: &Path,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<&Passphrase>,
    onboarding_password: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let package_raw = fs::read_to_string(package_path)
        .with_context(|| format!("read {}", package_path.display()))?;
    // C.5: env-var fallback removed; callers thread the onboarding password.
    let password =
        onboarding_password.ok_or_else(|| anyhow!("onboarding package password not provided"))?;
    let decoded = decode_bfonboard_package(&package_raw, password.as_str())
        .context("decode bfonboard package")?;
    let relay_profile_id = profile_domain(paths).ensure_onboarding_relay_profile(
        relay_profile,
        label.as_deref(),
        &decoded.relays,
        now_unix_secs(),
    )?;

    let encrypted_profile = store_encrypted_profile(
        paths,
        "onboarding_package",
        "file_import",
        &package_raw,
        passphrase,
    )?;
    let staged = StagedOnboardingImport {
        id: format!("onboarding-{}", now_unix_secs()),
        encrypted_profile_id: encrypted_profile.id.clone(),
        label,
        relay_profile: relay_profile_id,
        peer_pubkey: hex::encode(decoded.peer_pk),
        relays: decoded.relays,
        created_at: now_unix_secs(),
    };
    write_json(
        &paths.imports_dir.join(format!("{}.json", staged.id)),
        &staged,
    )?;

    Ok(ProfileImportResult::OnboardingStaged {
        encrypted_profile,
        staged_onboarding: staged,
        warnings: vec![
            "onboarding package staged in encrypted profile storage; final profile creation requires the ephemeral onboarding runtime".to_string(),
        ],
    })
}

pub async fn import_profile_from_onboarding_package(
    paths: &ShellPaths,
    package_path: &Path,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<Passphrase>,
    onboarding_password: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let package_raw = fs::read_to_string(package_path)
        .with_context(|| format!("read {}", package_path.display()))?;
    import_profile_from_onboarding_value(
        paths,
        &package_raw,
        label,
        relay_profile,
        passphrase,
        onboarding_password,
    )
    .await
}

pub async fn import_profile_from_onboarding_value(
    paths: &ShellPaths,
    package_raw: &str,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<Passphrase>,
    onboarding_password: Option<String>,
) -> Result<ProfileImportResult> {
    import_profile_from_onboarding_value_with(
        paths,
        package_raw,
        label,
        relay_profile,
        passphrase,
        onboarding_password,
        |decoded| async move { complete_onboarding_package(decoded, Duration::from_secs(30)).await },
    )
    .await
}

pub async fn connect_onboarding_package_preview(
    package_raw: &str,
    onboarding_password: String,
) -> Result<ConnectedOnboardingImport> {
    let decoded = decode_bfonboard_package(package_raw, onboarding_password.as_str())
        .context("decode bfonboard package")?;
    let completion = complete_onboarding_package(decoded, Duration::from_secs(30)).await?;
    let preview = preview_from_bootstrap_completion(
        &completion,
        None,
        "bfonboard",
        Some(completion.peer_pubkey.clone()),
    )?;
    Ok(ConnectedOnboardingImport {
        preview,
        completion,
    })
}

pub fn finalize_connected_onboarding_import(
    paths: &ShellPaths,
    connection: ConnectedOnboardingImport,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<Passphrase>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let relay_profile_id = profile_domain(paths).ensure_onboarding_relay_profile(
        relay_profile,
        label.as_deref(),
        &connection.completion.relays,
        now_unix_secs(),
    )?;
    let share_raw =
        serde_json::to_string_pretty(&SharePackageWire::from(connection.completion.share.clone()))
            .context("serialize onboarded share package")?;
    let share_record = store_encrypted_profile(
        paths,
        "share_package",
        "bfonboard_import",
        &share_raw,
        passphrase.as_ref(),
    )?;
    // Passphrase out of scope here — zeroized on drop.
    drop(passphrase);

    finalize_onboarding_import(
        paths,
        connection.completion,
        label,
        relay_profile_id,
        share_record,
    )
}

pub(crate) async fn import_profile_from_onboarding_value_with<F, Fut>(
    paths: &ShellPaths,
    package_raw: &str,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<Passphrase>,
    onboarding_password: Option<String>,
    complete: F,
) -> Result<ProfileImportResult>
where
    F: FnOnce(BfOnboardPayload) -> Fut,
    Fut: std::future::Future<Output = Result<BootstrapImportResult>>,
{
    paths.ensure()?;
    // C.5: env-var fallback removed; callers thread the onboarding password.
    let password =
        onboarding_password.ok_or_else(|| anyhow!("onboarding package password not provided"))?;
    let decoded = decode_bfonboard_package(package_raw, password.as_str())
        .context("decode bfonboard package")?;
    let completion = match complete(decoded).await {
        Ok(completion) => completion,
        Err(err) => return Err(err),
    };
    let preview = preview_from_bootstrap_completion(
        &completion,
        None,
        "bfonboard",
        Some(completion.peer_pubkey.clone()),
    )?;
    finalize_connected_onboarding_import(
        paths,
        ConnectedOnboardingImport {
            preview,
            completion,
        },
        label,
        relay_profile,
        passphrase,
    )
}

pub async fn run_setup(
    paths: &ShellPaths,
    request: SetupRequest,
    start_daemon: bool,
) -> Result<SetupResult> {
    let import = match (
        request.group_path.as_deref(),
        request.share_path.as_deref(),
        request.onboarding_package_path.as_deref(),
    ) {
        (Some(group), Some(share), None) => import_profile_from_files(
            paths,
            group,
            share,
            request.label,
            request.relay_profile,
            request.passphrase,
        )?,
        (None, None, Some(package)) => {
            import_profile_from_onboarding_package(
                paths,
                package,
                request.label,
                request.relay_profile,
                request.passphrase,
                request.onboarding_password,
            )
            .await?
        }
        _ => bail!(
            "setup requires both --group and --share; use `igloo-shell onboard` for onboarding packages"
        ),
    };

    let daemon = if start_daemon {
        match &import {
            ProfileImportResult::ProfileCreated { profile, .. } => {
                Some(start_profile_daemon(paths, &profile.id).await?)
            }
            ProfileImportResult::OnboardingStaged { .. } => None,
        }
    } else {
        None
    };

    Ok(SetupResult {
        import,
        daemon_started: daemon.is_some(),
        daemon,
    })
}

pub(crate) fn import_profile_from_bfprofile_payload(
    paths: &ShellPaths,
    payload: BfProfilePayload,
    label: Option<String>,
    relay_profile: Option<String>,
    passphrase: Option<Passphrase>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    // C.5: env-var fallback removed; callers thread the passphrase explicitly.
    let passphrase = passphrase.ok_or_else(|| anyhow!("passphrase not provided"))?;
    let relay_profile_id = ensure_onboarding_relay_profile(
        paths,
        relay_profile,
        Some(label.as_deref().unwrap_or(&payload.device.name)),
        &payload.device.relays,
    )?;
    let now = now_unix_secs();
    let imported = profile_domain(paths).import_profile_from_payload(
        &payload,
        label,
        Some(relay_profile_id),
        passphrase.expose_secret(),
        now,
    )?;
    Ok(ProfileImportResult::ProfileCreated {
        profile: imported.profile,
        encrypted_profile: imported.encrypted_profile,
        diagnostics: None,
        warnings: Vec::new(),
    })
}

fn finalize_onboarding_import(
    paths: &ShellPaths,
    completion: BootstrapImportResult,
    label: Option<String>,
    relay_profile_id: String,
    encrypted_profile: EncryptedProfileRecord,
) -> Result<ProfileImportResult> {
    let now = now_unix_secs();
    let imported = profile_domain(paths).finalize_onboarding_import(
        &completion.group,
        &completion.share,
        label,
        relay_profile_id,
        encrypted_profile,
        now,
    )?;
    let profile = imported.profile;
    let encrypted_profile = imported.encrypted_profile;
    // C.1: profile state dir holds nonce-pool and signer state. 0o700.
    #[cfg(unix)]
    bifrost_profile::fs_guard::ensure_dir_restricted(&paths.profile_state_dir(&profile.id), 0o700)
        .with_context(|| format!("create {}", paths.profile_state_dir(&profile.id).display()))?;
    #[cfg(not(unix))]
    fs::create_dir_all(paths.profile_state_dir(&profile.id))
        .with_context(|| format!("create {}", paths.profile_state_dir(&profile.id).display()))?;
    let diagnostics =
        match persist_validated_onboarding_state(Path::new(&profile.state_path), &completion) {
            Ok(report) => report,
            Err(error) => {
                let _ = fs::remove_file(&profile.group_ref);
                let _ = remove_encrypted_profile(paths, &encrypted_profile.id);
                let _ = fs::remove_dir_all(paths.profile_state_dir(&profile.id));
                return Err(error);
            }
        };
    write_profile(paths, &profile)?;
    touch_last_used_profile(paths, &profile.id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile,
        encrypted_profile,
        diagnostics: Some(
            serde_json::to_value(diagnostics).context("serialize onboarding diagnostics")?,
        ),
        warnings: Vec::new(),
    })
}
