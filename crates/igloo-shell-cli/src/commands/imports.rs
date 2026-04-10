use super::super::*;

pub async fn handle_import(paths: &ShellPaths, args: ImportArgs) -> Result<()> {
    let label = resolve_profile_label(args.label)?;
    let passphrase = resolve_secret_source_with(
        args.passphrase,
        args.passphrase_file,
        std::io::stdin().is_terminal(),
        "encrypted-profile-secret",
        "import requires passphrase input; use --passphrase / --passphrase-file, or run on a TTY",
        prompt_passphrase,
    )?;
    let relay_profile = if args.bfprofile_or_path.is_none() {
        ensure_relay_profile(
            paths,
            args.relay_profile.clone(),
            Some(label.as_str()),
            &args.relays,
        )?
    } else {
        args.relay_profile.clone()
    };
    let import = match (args.group, args.share, args.bfprofile_or_path) {
        (Some(group), Some(share), None) => import_profile_from_files(
            paths,
            std::path::Path::new(&group),
            std::path::Path::new(&share),
            Some(label.clone()),
            relay_profile,
            Some(passphrase.clone()),
        )?,
        (None, None, Some(package_or_path)) => {
            let package_raw = read_package_or_inline(&package_or_path)?;
            let package_secret = resolve_package_secret(
                args.package_secret,
                args.package_secret_file,
                "import requires package secret input; use --package-secret / --package-secret-file, or run on a TTY",
            )?;
            import_profile_from_bfprofile_value(
                paths,
                &package_raw,
                package_secret,
                Some(label.clone()),
                relay_profile,
                Some(passphrase.clone()),
            )?
        }
        _ => bail!("import requires either <bfprofile-or-path> or both --group and --share"),
    };
    if let Ok(profile) = result_profile(&import) {
        if let Err(err) = publish_profile_backup(paths, &profile.id, None).await {
            eprintln!("warning: failed to publish encrypted profile backup: {err}");
        }
        let daemon = if args.daemon {
            let (metadata, existing) =
                ensure_profile_daemon(paths, &profile.id, Some(passphrase.clone())).await?;
            Some((metadata, existing))
        } else {
            None
        };
        if args.json {
            return print_json(&serde_json::json!({
                "import": import,
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
            return start_profile_attached(paths, profile, passphrase).await;
        }
        if let Some((metadata, existing)) = daemon {
            print_profile_ready_summary("Import complete.", profile);
            print_daemon_started_summary(profile, &metadata, existing);
            return Ok(());
        }
        print_profile_ready_summary("Import complete.", profile);
        print_profile_next_commands(&profile.id);
        return Ok(());
    }
    print_json(&import)
}

pub fn handle_export(paths: &ShellPaths, args: ExportArgs) -> Result<()> {
    let passphrase = load_secret_from_env(args.passphrase_env)?;
    let result = match args.format.as_str() {
        "raw" => serde_json::to_value(export_profile(
            paths,
            &args.profile_id,
            std::path::Path::new(&args.out),
            passphrase,
        )?)?,
        "bfprofile" => serde_json::to_value(export_profile_as_bfprofile(
            paths,
            &args.profile_id,
            require_env_secret(args.package_password_env, "package password")?,
            passphrase,
            Some(std::path::Path::new(&args.out)),
        )?)?,
        "bfshare" => serde_json::to_value(export_profile_as_bfshare(
            paths,
            &args.profile_id,
            require_env_secret(args.package_password_env, "package password")?,
            passphrase,
            Some(std::path::Path::new(&args.out)),
        )?)?,
        "bfonboard" => {
            serde_json::to_value(export_profile_as_bfonboard(
                paths,
                &args.profile_id,
                std::path::Path::new(&args.recipient_share.ok_or_else(|| {
                    anyhow!("--recipient-share is required for --format bfonboard")
                })?),
                if args.relay_urls.is_empty() {
                    None
                } else {
                    Some(args.relay_urls)
                },
                require_env_secret(args.package_password_env, "package password")?,
                passphrase,
                Some(std::path::Path::new(&args.out)),
            )?)?
        }
        _ => bail!(
            "unsupported profile export format {}; expected raw, bfprofile, bfshare, or bfonboard",
            args.format
        ),
    };
    print_json(&result)
}

pub async fn handle_recover(paths: &ShellPaths, args: RecoverArgs) -> Result<()> {
    let package_raw = read_package_or_inline(&args.bfshare_or_path)?;
    let package_secret = resolve_package_secret(
        args.package_secret,
        args.package_secret_file,
        "recover requires package secret input; use --package-secret / --package-secret-file, or run on a TTY",
    )?;
    let passphrase = resolve_secret_source_with(
        args.passphrase,
        args.passphrase_file,
        std::io::stdin().is_terminal(),
        "encrypted-profile-secret",
        "recover requires passphrase input; use --passphrase / --passphrase-file, or run on a TTY",
        prompt_passphrase,
    )?;
    let label = resolve_profile_label(args.label)?;
    let import = recover_profile_from_bfshare_value(
        paths,
        &package_raw,
        package_secret,
        Some(label),
        None,
        Some(passphrase.clone()),
    )
    .await?;
    if let Ok(profile) = result_profile(&import) {
        if let Err(err) = publish_profile_backup(paths, &profile.id, None).await {
            eprintln!("warning: failed to publish encrypted profile backup: {err}");
        }
        let daemon = if args.daemon {
            let (metadata, existing) =
                ensure_profile_daemon(paths, &profile.id, Some(passphrase.clone())).await?;
            Some((metadata, existing))
        } else {
            None
        };
        if args.json {
            return print_json(&serde_json::json!({
                "import": import,
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
            return start_profile_attached(paths, profile, passphrase).await;
        }
        if let Some((metadata, existing)) = daemon {
            print_profile_ready_summary("Recovery complete.", profile);
            print_daemon_started_summary(profile, &metadata, existing);
            return Ok(());
        }
        print_profile_ready_summary("Recovery complete.", profile);
        print_profile_next_commands(&profile.id);
        return Ok(());
    }
    print_json(&import)
}

pub async fn handle_setup(paths: &ShellPaths, args: SetupArgs) -> Result<()> {
    let relay_profile = ensure_relay_profile(
        paths,
        args.relay_profile,
        args.label.as_deref(),
        &args.relays,
    )?;
    let result = run_setup(
        paths,
        SetupRequest {
            group_path: args.group.map(Into::into),
            share_path: args.share.map(Into::into),
            onboarding_package_path: None,
            label: args.label,
            relay_profile,
            passphrase: load_secret_from_env(args.passphrase_env)?,
            onboarding_password: None,
        },
        args.start_daemon,
    )
    .await?;
    print_json(&result)
}

pub async fn handle_onboard(paths: &ShellPaths, args: OnboardArgs) -> Result<()> {
    let package_raw = read_package_or_inline(&args.package_or_path)?;
    let label = resolve_profile_label(args.label)?;
    let onboarding_secret = resolve_onboard_secret(args.onboard_secret, args.onboard_secret_file)?;
    let passphrase = resolve_passphrase(args.passphrase, args.passphrase_file)?;
    let import = import_profile_from_onboarding_value(
        paths,
        &package_raw,
        Some(label),
        None,
        Some(passphrase.clone()),
        Some(onboarding_secret),
    )
    .await?;
    let profile = result_profile(&import)?;
    let profile_id = profile.id.clone();
    let daemon = if args.daemon {
        let (metadata, existing) =
            ensure_profile_daemon(paths, &profile_id, Some(passphrase.clone())).await?;
        Some((metadata, existing))
    } else {
        None
    };

    if args.json {
        print_json(&serde_json::json!({
            "import": import,
            "daemon": daemon.as_ref().map(|(metadata, existing)| serde_json::json!({
                "started": !existing,
                "metadata": metadata,
            })),
            "next": {
                "load": format!("igloo-shell profile load {}", profile_id),
                "start": format!("igloo-shell profile load {} --start", profile_id),
                "daemon": format!("igloo-shell profile load {} --daemon", profile_id),
            }
        }))
    } else {
        if args.start {
            return start_profile_attached(paths, profile, passphrase).await;
        }
        if let Some((metadata, existing)) = daemon {
            print_profile_ready_summary("Onboarding complete.", profile);
            print_daemon_started_summary(profile, &metadata, existing);
            Ok(())
        } else {
            print_profile_ready_summary("Onboarding complete.", profile);
            print_profile_next_commands(&profile_id);
            Ok(())
        }
    }
}
