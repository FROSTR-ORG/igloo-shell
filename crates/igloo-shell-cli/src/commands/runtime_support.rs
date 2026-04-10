use super::super::*;
use bifrost_app::native_runtime::DaemonMetadata;
use bifrost_profile::{ProfileImportResult, ProfileManifest};

pub async fn ensure_profile_daemon(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<(DaemonMetadata, bool)> {
    if let Ok(metadata) = read_daemon_metadata(paths, profile_id) {
        if daemon_runtime_metadata(paths, profile_id).await.is_ok() {
            return Ok((metadata, true));
        }
        let _ = remove_daemon_metadata(paths, profile_id);
    }

    let metadata = if let Some(secret) = passphrase {
        start_profile_daemon_with_passphrase(paths, profile_id, Some(secret)).await?
    } else {
        start_profile_daemon(paths, profile_id).await?
    };
    Ok((metadata, false))
}

pub async fn start_profile_attached(
    paths: &ShellPaths,
    profile: &ProfileManifest,
    passphrase: String,
) -> Result<()> {
    let (metadata, existing) = ensure_profile_daemon(paths, &profile.id, Some(passphrase)).await?;
    super::output::print_daemon_started_summary(profile, &metadata, existing);
    println!("Streaming daemon log. Press Ctrl-C to exit.");
    super::output::follow_log_file(Path::new(&metadata.log_path)).await
}

pub fn result_profile(
    result: &ProfileImportResult,
) -> Result<&ProfileManifest> {
    match result {
        ProfileImportResult::ProfileCreated { profile, .. } => Ok(profile),
        ProfileImportResult::OnboardingStaged { .. } => {
            bail!("onboarding did not create a profile")
        }
    }
}

pub fn ensure_relay_profile(
    paths: &ShellPaths,
    relay_profile: Option<String>,
    label: Option<&str>,
    relays: &[String],
) -> Result<Option<String>> {
    if relays.is_empty() {
        return Ok(relay_profile);
    }

    let profile_id = relay_profile
        .unwrap_or_else(|| {
            format!(
                "relay-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0)
            )
        });
    replace_relay_profile(
        paths,
        RelayProfile {
            id: profile_id.clone(),
            label: label.unwrap_or(&profile_id).to_string(),
            relays: relays.to_vec(),
        },
    )?;
    Ok(Some(profile_id))
}
