use super::super::*;

pub async fn handle_daemon(paths: &ShellPaths, command: DaemonCommands) -> Result<()> {
    match command {
        DaemonCommands::Start {
            profile,
            passphrase,
            passphrase_file,
        } => {
            // C.5: collect the passphrase via --passphrase / --passphrase-file
            // / TTY prompt / piped stdin and hand it to the daemon spawn,
            // which pipes it through stdin to the child.
            let passphrase = resolve_passphrase_source_with(
                passphrase,
                passphrase_file,
                std::io::stdin().is_terminal(),
                "encrypted-profile-secret",
                "daemon start requires passphrase input; use --passphrase / --passphrase-file, pipe it via stdin, or run on a TTY",
                prompt_load_passphrase,
            )?;
            let metadata =
                start_profile_daemon_with_passphrase(paths, &profile, Some(passphrase)).await?;
            print_json(&metadata)
        }
        DaemonCommands::Stop { profile } => {
            let result = stop_profile_daemon_typed(paths, &profile).await?;
            print_json(&serde_json::json!({
                "stopped": true,
                "profile": profile,
                "result": result,
            }))
        }
        DaemonCommands::Restart {
            profile,
            passphrase,
            passphrase_file,
        } => {
            let passphrase = resolve_passphrase_source_with(
                passphrase,
                passphrase_file,
                std::io::stdin().is_terminal(),
                "encrypted-profile-secret",
                "daemon restart requires passphrase input; use --passphrase / --passphrase-file, pipe it via stdin, or run on a TTY",
                prompt_load_passphrase,
            )?;
            let _ = stop_profile_daemon(paths, &profile).await;
            let metadata =
                start_profile_daemon_with_passphrase(paths, &profile, Some(passphrase)).await?;
            print_json(&serde_json::json!({
                "restarted": true,
                "profile": profile,
                "metadata": metadata,
            }))
        }
        DaemonCommands::Status { profile } => {
            if let Some(profile_id) = profile {
                let metadata = read_daemon_metadata(paths, &profile_id)?;
                let runtime = daemon_runtime_metadata(paths, &profile_id).await?;
                print_json(&serde_json::json!({
                    "profile": profile_id,
                    "metadata": metadata,
                    "runtime": runtime,
                }))
            } else {
                let profiles = list_profiles(paths)?;
                let mut statuses = Vec::new();
                for profile in profiles {
                    if let Ok(metadata) = read_daemon_metadata(paths, &profile.id) {
                        statuses.push(serde_json::json!({
                            "profile": profile.id,
                            "metadata": metadata,
                        }));
                    }
                }
                print_json(&statuses)
            }
        }
        DaemonCommands::Logs { profile, follow } => {
            let log_path = daemon_log_path(paths, &profile);
            if follow {
                return follow_log_file(&log_path).await;
            }
            print_json(&serde_json::json!({
                "profile": profile,
                "log_path": log_path,
            }))
        }
    }
}

pub async fn handle_runtime(paths: &ShellPaths, command: RuntimeCommands) -> Result<()> {
    match command {
        RuntimeCommands::Status { profile } => {
            let status = daemon_runtime_status(paths, &profile).await?;
            print_json(&status)
        }
        RuntimeCommands::Diagnostics { profile } => {
            let diagnostics = daemon_runtime_diagnostics(paths, &profile).await?;
            print_json(&diagnostics)
        }
        RuntimeCommands::Ops { profile } => {
            let metadata = daemon_runtime_metadata(paths, &profile).await?;
            print_json(&serde_json::json!({
                "profile": profile,
                "runtime_metadata": metadata,
            }))
        }
        RuntimeCommands::Sign {
            profile,
            message_hex32,
        } => {
            let result = daemon_sign(paths, &profile, message_hex32).await?;
            print_json(&result)
        }
        RuntimeCommands::Ecdh {
            profile,
            pubkey_hex32,
        } => {
            let result = daemon_ecdh(paths, &profile, pubkey_hex32).await?;
            print_json(&result)
        }
        RuntimeCommands::WipeState { profile, yes } => {
            if !yes {
                bail!("runtime wipe-state requires --yes");
            }
            let result = daemon_wipe_state(paths, &profile).await?;
            print_json(&result)
        }
    }
}

pub async fn handle_check(paths: &ShellPaths, command: CheckCommands) -> Result<()> {
    let result = match command {
        CheckCommands::Onboard { profile } => {
            check_profile_runtime(paths, &profile, ShellCheckKind::Onboard).await?
        }
        CheckCommands::Sign { profile } => {
            check_profile_runtime(paths, &profile, ShellCheckKind::Sign).await?
        }
        CheckCommands::Ecdh { profile } => {
            check_profile_runtime(paths, &profile, ShellCheckKind::Ecdh).await?
        }
    };
    print_json(&result)
}

pub async fn handle_peer(paths: &ShellPaths, command: PeerCommands) -> Result<()> {
    match command {
        PeerCommands::List { profile } => {
            let result = daemon_peer_status(paths, &profile).await?;
            print_json(&result)
        }
        PeerCommands::Ping {
            profile,
            peer_pubkey,
        } => {
            let result = daemon_ping(paths, &profile, peer_pubkey).await?;
            print_json(&result)
        }
        PeerCommands::Onboard {
            profile,
            peer_pubkey,
        } => {
            let result = daemon_onboard(paths, &profile, peer_pubkey).await?;
            print_json(&result)
        }
    }
}

pub async fn handle_policy(paths: &ShellPaths, command: PolicyCommands) -> Result<()> {
    match command {
        PolicyCommands::Show { profile } => {
            let result = daemon_runtime_status(paths, &profile).await?;
            print_json(&result.peer_permission_states)
        }
        PolicyCommands::SetDefaultOverride {
            profile,
            direction,
            method,
            value,
        } => {
            let profile = set_profile_default_policy_override(
                paths,
                &profile,
                policy_direction(direction),
                policy_method(method),
                policy_value(value),
            )?;
            print_json(&serde_json::json!({
                "updated": true,
                "profile": profile.id,
                "restart_required": true,
                "manifest": profile,
            }))
        }
        PolicyCommands::SetPeerOverride {
            profile,
            peer_pubkey,
            direction,
            method,
            value,
        } => {
            let (manifest, effective_override) = set_profile_peer_policy_override(
                paths,
                &profile,
                &peer_pubkey,
                policy_direction(direction),
                policy_method(method),
                policy_value(value),
            )?;
            let result =
                daemon_set_policy_override(paths, &profile, peer_pubkey, &effective_override)
                    .await?;
            print_json(&serde_json::json!({
                "updated": true,
                "persisted": true,
                "profile": manifest.id,
                "result": result,
            }))
        }
        PolicyCommands::ClearPeer {
            profile,
            peer_pubkey,
        } => {
            let (manifest, effective_override) =
                clear_profile_peer_policy(paths, &profile, &peer_pubkey)?;
            let result =
                daemon_set_policy_override(paths, &profile, peer_pubkey, &effective_override)
                    .await?;
            print_json(&serde_json::json!({
                "updated": true,
                "persisted": true,
                "profile": manifest.id,
                "result": result,
            }))
        }
    }
}

pub async fn handle_relays(paths: &ShellPaths, command: RelayCommands) -> Result<()> {
    match command {
        RelayCommands::List => print_relay_profiles(paths),
        RelayCommands::Set(args) => {
            if args.relays.is_empty() {
                bail!("relays set requires at least one relay");
            }
            let label = args.label.unwrap_or_else(|| args.profile_id.clone());
            replace_relay_profile(
                paths,
                RelayProfile {
                    id: args.profile_id,
                    label,
                    relays: args.relays,
                },
            )?;
            print_relay_profiles(paths)
        }
        RelayCommands::Add(args) => {
            if args.relays.is_empty() {
                bail!("relays add requires at least one relay");
            }
            add_relays(paths, &args.profile_id, &args.relays)?;
            print_relay_profiles(paths)
        }
        RelayCommands::Remove(args) => {
            if args.relays.is_empty() {
                bail!("relays remove requires at least one relay");
            }
            remove_relays(paths, &args.profile_id, &args.relays)?;
            print_relay_profiles(paths)
        }
        RelayCommands::Default { profile_id } => {
            set_default_relay_profile(paths, &profile_id)?;
            print_relay_profiles(paths)
        }
        RelayCommands::Test { relay_profile } => {
            let result = test_relay_connectivity(paths, relay_profile).await?;
            print_json(&result)
        }
    }
}
