use super::super::*;
use bifrost_app::native_runtime::DaemonMetadata;
use bifrost_profile::ProfileManifest;

pub fn short_profile_id(profile_id: &str) -> &str {
    &profile_id[..profile_id.len().min(8)]
}

pub fn print_profile_ready_summary(prefix: &str, profile: &ProfileManifest) {
    println!(
        "{prefix} Profile \"{}\" ({}) is ready.",
        profile.label,
        short_profile_id(&profile.id)
    );
}

pub fn print_profile_next_commands(profile_id: &str) {
    println!("Next commands:");
    println!("  igloo-shell profile load {profile_id}");
    println!("  igloo-shell profile load {profile_id} --start");
    println!("  igloo-shell profile load {profile_id} --daemon");
    println!("  igloo-shell daemon status --profile {profile_id}");
}

pub fn print_rotation_workspace_status(status: &igloo_shell_core::shell::RotationWorkspaceStatus) {
    println!("Rotation workspace: {}", status.workspace_path);
    println!(
        "Source profile: {} | source group: {}",
        status.source_profile_id,
        short_profile_id(&status.source_group_id)
    );
    println!(
        "Sources: {}/{} | targets: {} | remote packages: {}",
        status.source_packages_present,
        status.source_packages_required,
        status.next_count,
        status.remote_target_count
    );
    if let Some(member_index) = status.local_target_member_index {
        println!("Local replacement member: {member_index}");
    }
    if let Some(profile_id) = &status.local_replace_profile_id {
        println!("Local replace profile: {}", short_profile_id(profile_id));
    }
    if status.ready {
        println!("Workspace is ready for generation.");
    } else {
        println!("Workspace is not ready yet.");
    }
    if !status.missing_secret_entries.is_empty() {
        println!("Missing source package secret references:");
        for entry in &status.missing_secret_entries {
            println!("  {entry}");
        }
    }
    if !status.validation_errors.is_empty() {
        println!("Validation errors:");
        for error in &status.validation_errors {
            println!("  {error}");
        }
    }
}

pub fn print_rotation_generated_packages(result: &igloo_shell_core::shell::RotationGenerateResult) {
    if result.generated_packages.is_empty() {
        println!("No remote onboarding packages were generated.");
        return;
    }
    println!("Generated onboarding packages:");
    for package in &result.generated_packages {
        println!(
            "  member {} | {} | {} | {}",
            package.member_index,
            package.label,
            match package.usage_hint {
                igloo_shell_core::shell::RotationUsageHint::NewDevice => "new_device",
                igloo_shell_core::shell::RotationUsageHint::RotateExistingDevice => {
                    "rotate_existing_device"
                }
            },
            package.path
        );
    }
}

pub fn print_running_profile_commands(profile_id: &str) {
    println!("Useful status commands:");
    println!("  igloo-shell daemon status --profile {profile_id}");
    println!("  igloo-shell runtime status --profile {profile_id}");
    println!("  igloo-shell peer list --profile {profile_id}");
    println!("  igloo-shell policy show --profile {profile_id}");
    println!("  igloo-shell daemon logs --profile {profile_id} --follow");
}

pub fn print_daemon_started_summary(
    profile: &ProfileManifest,
    metadata: &DaemonMetadata,
    existing: bool,
) {
    let state = if existing {
        "already running"
    } else {
        "started"
    };
    println!(
        "Daemon {state} for \"{}\" ({}).",
        profile.label,
        short_profile_id(&profile.id)
    );
    println!("  pid: {}", metadata.pid);
    println!("  socket: {}", metadata.socket_path);
    println!("  log: {}", metadata.log_path);
    print_running_profile_commands(&profile.id);
}

pub fn print_profile_load_summary(paths: &ShellPaths, profile: &ProfileManifest) -> Result<()> {
    println!(
        "Profile loaded: \"{}\" ({})",
        profile.label,
        short_profile_id(&profile.id)
    );
    println!("Passphrase accepted.");
    let daemon_state = if read_daemon_metadata(paths, &profile.id).is_ok() {
        "running or recorded"
    } else {
        "not running"
    };
    println!("Daemon: {daemon_state}");
    print_profile_next_commands(&profile.id);
    Ok(())
}

pub fn print_relay_profiles(paths: &ShellPaths) -> Result<()> {
    let config = load_shell_config(paths)?;
    let profiles = load_relay_profiles(paths)?;
    print_json(&serde_json::json!({
        "default_relay_profile_id": config.default_relay_profile_id,
        "profiles": profiles,
    }))
}

pub async fn follow_log_file(path: &Path) -> Result<()> {
    let mut file = File::open(path).map_err(|e| anyhow!("open {}: {e}", path.display()))?;
    let mut offset = 0u64;
    let mut buffer = Vec::new();

    loop {
        file.seek(SeekFrom::Start(offset))?;
        buffer.clear();
        file.read_to_end(&mut buffer)?;
        if !buffer.is_empty() {
            print!("{}", String::from_utf8_lossy(&buffer));
            offset += u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
}

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
