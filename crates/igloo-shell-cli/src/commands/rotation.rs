use super::super::*;

pub async fn handle_rotate_keyset(paths: &ShellPaths, command: RotateKeysetCommands) -> Result<()> {
    match command {
        RotateKeysetCommands::Init(args) => handle_rotate_keyset_init(paths, args),
        RotateKeysetCommands::Show(args) => handle_rotate_keyset_show(paths, args),
        RotateKeysetCommands::Generate(args) => handle_rotate_keyset_generate(paths, args).await,
    }
}

pub async fn handle_rotate_key(paths: &ShellPaths, args: RotateKeyArgs) -> Result<()> {
    let package_raw = read_package_or_inline(&args.package_or_path)?;
    let passphrase = resolve_passphrase(args.passphrase, args.passphrase_file)?;
    let onboarding_secret = resolve_onboard_secret(args.onboard_secret, args.onboard_secret_file)?;
    let target = read_profile(paths, &args.profile)?;
    let old_profile_id = target.id.clone();

    let import = apply_rotation_update_from_bfonboard_value(
        paths,
        &old_profile_id,
        &package_raw,
        onboarding_secret,
        Some(&passphrase),
    )
    .await?;

    let profile = result_profile(&import)?;
    let new_profile_id = profile.id.clone();

    if let Err(err) = publish_profile_backup(paths, &new_profile_id, None).await {
        eprintln!("warning: failed to publish encrypted profile backup: {err}");
    }

    let daemon = if args.daemon {
        // passphrase cloned: ensure_profile_daemon owns the stdin handoff;
        // we keep our `passphrase` for the optional follow-on `--start`.
        let (metadata, existing) =
            ensure_profile_daemon(paths, &new_profile_id, Some(passphrase.clone_secret())).await?;
        Some((metadata, existing))
    } else {
        None
    };

    if args.json {
        return print_json(&serde_json::json!({
            "import": import,
            "rotation_update": {
                "replaced_profile_id": old_profile_id,
                "profile_id": new_profile_id,
            },
            "daemon": daemon.as_ref().map(|(metadata, existing)| serde_json::json!({
                "started": !existing,
                "metadata": metadata,
            })),
            "next": {
                "load": format!("igloo-shell profile load {}", profile.id),
                "start": format!("igloo-shell profile load {} --start", profile.id),
                "daemon": format!("igloo-shell profile load {} --daemon", profile.id),
            }
        }));
    }

    if args.start {
        println!(
            "Rotation update complete. Replaced profile {} with {}.",
            short_profile_id(&old_profile_id),
            short_profile_id(&new_profile_id)
        );
        return start_profile_attached(paths, profile, passphrase).await;
    }

    print_profile_ready_summary("Rotation update complete.", profile);
    println!(
        "Replaced profile {} with {}.",
        short_profile_id(&old_profile_id),
        short_profile_id(&new_profile_id)
    );
    if let Some((metadata, existing)) = daemon {
        print_daemon_started_summary(profile, &metadata, existing);
        return Ok(());
    }
    print_profile_next_commands(&new_profile_id);
    Ok(())
}

fn handle_rotate_keyset_init(paths: &ShellPaths, args: RotateKeysetInitArgs) -> Result<()> {
    let stdin_is_terminal = std::io::stdin().is_terminal();
    let passphrase = resolve_passphrase_source_with(
        args.passphrase,
        args.passphrase_file,
        stdin_is_terminal,
        "encrypted-profile-secret",
        "rotate-keyset init requires passphrase input; use --passphrase / --passphrase-file, pipe it via stdin, or run on a TTY",
        prompt_load_passphrase,
    )?;
    let workspace_root = args
        .workspace
        .map(PathBuf::from)
        .unwrap_or_else(|| default_rotation_workspace_path(paths, &args.profile));
    let document = create_rotation_workspace(
        paths,
        &args.profile,
        args.threshold,
        args.count,
        &workspace_root,
        args.source_bfshares,
        Some(&passphrase),
    )?;
    let status = inspect_rotation_workspace(&workspace_root, &document);
    if args.json {
        return print_json(&serde_json::json!({
            "workspace": workspace_root.display().to_string(),
            "document": document,
            "status": status,
        }));
    }

    println!(
        "Rotation workspace created at {}.",
        workspace_root.display()
    );
    print_rotation_workspace_status(&status);
    Ok(())
}

fn handle_rotate_keyset_show(paths: &ShellPaths, args: RotateKeysetShowArgs) -> Result<()> {
    let _ = paths;
    let workspace_root = PathBuf::from(args.workspace);
    let document = load_rotation_workspace(&workspace_root)?;
    let status = inspect_rotation_workspace(&workspace_root, &document);
    if args.json {
        return print_json(&serde_json::json!({
            "workspace": workspace_root.display().to_string(),
            "document": document,
            "status": status,
        }));
    }

    print_rotation_workspace_status(&status);
    Ok(())
}

async fn handle_rotate_keyset_generate(
    paths: &ShellPaths,
    args: RotateKeysetGenerateArgs,
) -> Result<()> {
    let workspace_root = PathBuf::from(&args.workspace);
    let document = load_rotation_workspace(&workspace_root)?;
    let stdin_is_terminal = std::io::stdin().is_terminal();
    let passphrase = resolve_passphrase_source_with(
        args.passphrase,
        args.passphrase_file,
        stdin_is_terminal,
        "encrypted-profile-secret",
        "rotate-keyset generate requires passphrase input; use --passphrase / --passphrase-file, pipe it via stdin, or run on a TTY",
        prompt_load_passphrase,
    )?;
    let source_passwords = resolve_rotation_source_passwords(&document, stdin_is_terminal)?;
    let needs_distribution_secret = document
        .targets
        .iter()
        .any(|target| target.mode != igloo_shell_core::shell::RotationTargetMode::LocalReplace);
    let distribution_secret = if needs_distribution_secret {
        Some(resolve_secret_source_with(
            args.distribution_secret,
            args.distribution_secret_file,
            stdin_is_terminal,
            "distribution-secret",
            "rotate-keyset generate requires onboarding package secret input; use --distribution-secret / --distribution-secret-file, or run on a TTY",
            || prompt_distribution_secret().map(|p| p.expose_secret().to_string()),
        )?)
    } else {
        None
    };

    let result = generate_rotation_workspace(
        paths,
        &workspace_root,
        source_passwords,
        Some(&passphrase),
        distribution_secret,
    )
    .await?;

    let daemon = if args.daemon {
        // passphrase cloned: ensure_profile_daemon owns the stdin handoff.
        let (metadata, existing) =
            ensure_profile_daemon(paths, &result.profile.id, Some(passphrase.clone_secret()))
                .await?;
        Some((metadata, existing))
    } else {
        None
    };

    if args.json {
        return print_json(&serde_json::json!({
            "rotation_generate": result,
            "daemon": daemon.as_ref().map(|(metadata, existing)| serde_json::json!({
                "started": !existing,
                "metadata": metadata,
            })),
            "next": {
                "load": format!("igloo-shell profile load {}", result.profile.id),
                "start": format!("igloo-shell profile load {} --start", result.profile.id),
                "daemon": format!("igloo-shell profile load {} --daemon", result.profile.id),
            }
        }));
    }

    if args.start {
        println!(
            "Rotation generated. Replaced profile {} with {}.",
            short_profile_id(&result.replaced_profile_id),
            short_profile_id(&result.profile.id)
        );
        print_rotation_generated_packages(&result);
        return start_profile_attached(paths, &result.profile, passphrase).await;
    }

    print_profile_ready_summary("Rotation generation complete.", &result.profile);
    println!(
        "Replaced profile {} with {}.",
        short_profile_id(&result.replaced_profile_id),
        short_profile_id(&result.profile.id)
    );
    print_rotation_generated_packages(&result);
    if let Some((metadata, existing)) = daemon {
        print_daemon_started_summary(&result.profile, &metadata, existing);
        return Ok(());
    }
    print_profile_next_commands(&result.profile.id);
    Ok(())
}

pub async fn handle_keygen(paths: &ShellPaths, args: KeygenArgs) -> Result<()> {
    let stdin_is_terminal = std::io::stdin().is_terminal();
    let group_name = resolve_required_text(
        args.group_name,
        stdin_is_terminal,
        "keygen requires --group-name when stdin is not a TTY",
        prompt_group_name,
    )?;
    let threshold = resolve_u16_input(
        args.threshold,
        stdin_is_terminal,
        "threshold",
        "keygen requires --threshold when stdin is not a TTY",
        prompt_threshold,
    )?;
    let count = resolve_u16_input(
        args.count,
        stdin_is_terminal,
        "count",
        "keygen requires --count when stdin is not a TTY",
        prompt_count,
    )?;
    let draft = create_generated_keyset_draft(group_name, threshold, count)?;
    let member_index = resolve_member_index(
        args.member_index,
        &draft,
        stdin_is_terminal,
        "keygen requires --member-index when stdin is not a TTY",
    )?;
    let default_label = draft
        .shares
        .iter()
        .find(|share| share.member_idx == member_index)
        .map(|share| share.label.clone());
    let label = resolve_required_text(
        args.label.or(default_label),
        stdin_is_terminal,
        "keygen requires --label when stdin is not a TTY",
        prompt_profile_label,
    )?;
    let relay_urls = resolve_keygen_relays(args.relay_urls, stdin_is_terminal)?;
    let passphrase = resolve_passphrase_source_with(
        args.passphrase,
        args.passphrase_file,
        stdin_is_terminal,
        "encrypted-profile-secret",
        "keygen requires passphrase input; use --passphrase / --passphrase-file, pipe it via stdin, or run on a TTY",
        prompt_passphrase,
    )?;
    let distribution_secret = resolve_secret_source_with(
        args.distribution_secret,
        args.distribution_secret_file,
        stdin_is_terminal,
        "distribution-secret",
        "keygen requires onboarding package secret input; use --distribution-secret / --distribution-secret-file, or run on a TTY",
        || prompt_distribution_secret().map(|p| p.expose_secret().to_string()),
    )?;
    let import = import_generated_share(
        paths,
        &draft,
        member_index,
        label,
        relay_urls.clone(),
        // passphrase cloned: bifrost-profile consumes the Passphrase for
        // the encrypted profile envelope; we keep ours for the backup +
        // daemon spawn below.
        Some(passphrase.clone_secret()),
    )?;
    let profile = result_profile(&import)?.clone();
    if let Err(err) = publish_profile_backup(paths, &profile.id, None).await {
        eprintln!("warning: failed to publish encrypted profile backup: {err}");
    }
    let export_root = paths
        .state_dir
        .join("generated-onboarding")
        .join(&profile.id);
    // C.1: directory holds generated onboarding packages; tighten to 0o700.
    #[cfg(unix)]
    bifrost_profile::fs_guard::ensure_dir_restricted(&export_root, 0o700)
        .with_context(|| format!("create {}", export_root.display()))?;
    #[cfg(not(unix))]
    fs::create_dir_all(&export_root)
        .with_context(|| format!("create {}", export_root.display()))?;
    let selected_share = draft
        .shares
        .iter()
        .find(|share| share.member_idx == member_index)
        .ok_or_else(|| anyhow!("generated share {member_index} not found"))?;
    let mut packages = Vec::new();
    for share in &draft.shares {
        if share.member_idx == member_index {
            continue;
        }
        let package = export_generated_onboarding_package(
            &draft,
            share.member_idx,
            relay_urls.clone(),
            selected_share.share_public_key.clone(),
            distribution_secret.clone(),
        )?;
        let path = export_root.join(format!("member-{}.bfonboard.txt", share.member_idx));
        // C.1: bfonboard packages are encrypted but treated as secret-bearing.
        // Atomic 0o600 write via fs_guard.
        #[cfg(unix)]
        bifrost_profile::fs_guard::write_restricted_bytes_atomic(&path, package.as_bytes(), 0o600)
            .with_context(|| format!("write {}", path.display()))?;
        #[cfg(not(unix))]
        fs::write(&path, &package).with_context(|| format!("write {}", path.display()))?;
        packages.push(serde_json::json!({
            "member_idx": share.member_idx,
            "label": share.label,
            "path": path.display().to_string(),
        }));
    }
    if args.json {
        return print_json(&serde_json::json!({
            "import": import,
            "generated_packages": packages,
            "next": {
                "load": format!("igloo-shell profile load {}", profile.id),
                "start": format!("igloo-shell profile load {} --start", profile.id),
                "daemon": format!("igloo-shell profile load {} --daemon", profile.id),
            }
        }));
    }
    println!(
        "Keyset generated. Saved onboarding packages for the remaining members under {}.",
        export_root.display()
    );
    print_profile_ready_summary("Local profile created.", &profile);
    print_profile_next_commands(&profile.id);
    Ok(())
}
