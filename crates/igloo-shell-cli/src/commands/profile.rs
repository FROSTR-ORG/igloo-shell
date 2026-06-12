use super::super::*;

pub async fn handle_profile(paths: &ShellPaths, command: ProfileCommands) -> Result<()> {
    match command {
        ProfileCommands::List => {
            let profiles = list_profiles(paths)?;
            print_json(&profiles)
        }
        ProfileCommands::Show { profile_id } => {
            let profile = read_profile(paths, &profile_id)?;
            print_json(&profile)
        }
        ProfileCommands::Load(args) => handle_load(paths, args).await,
        ProfileCommands::Remove { profile_id, yes } => {
            if !yes {
                bail!("profile remove requires --yes");
            }
            remove_profile(paths, &profile_id)?;
            print_json(&serde_json::json!({
                "removed": true,
                "profile_id": profile_id,
            }))
        }
        ProfileCommands::Doctor { profile_id } => {
            let profile = read_profile(paths, &profile_id)?;
            let report = doctor_profile(paths, &profile)?;
            print_json(&report)
        }
    }
}

pub async fn handle_load(paths: &ShellPaths, args: LoadArgs) -> Result<()> {
    let mode = load_mode(&args);
    let profile_id = match args.profile_id {
        Some(profile_id) => {
            let _ = read_profile(paths, &profile_id)?;
            profile_id
        }
        None => prompt_select_profile(paths)?,
    };
    let passphrase = resolve_passphrase_source_with(
        args.passphrase,
        args.passphrase_file,
        std::io::stdin().is_terminal(),
        "encrypted-profile-secret",
        "profile load requires passphrase input; use --passphrase / --passphrase-file, pipe it via stdin, or run on a TTY",
        prompt_load_passphrase,
    )?;
    let profile = read_profile(paths, &profile_id)?;
    validate_profile_unlock_with_passphrase(paths, &profile_id, Some(&passphrase))?;
    match mode {
        LoadMode::StatusOnly => {
            print_profile_load_summary(paths, &profile)?;
            Ok(())
        }
        LoadMode::StartAttached => start_profile_attached(paths, &profile, passphrase).await,
        LoadMode::StartBackground => {
            let (metadata, existing) =
                ensure_profile_daemon(paths, &profile.id, Some(passphrase)).await?;
            print_daemon_started_summary(&profile, &metadata, existing);
            Ok(())
        }
    }
}
