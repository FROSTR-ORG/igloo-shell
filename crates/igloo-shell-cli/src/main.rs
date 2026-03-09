use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use bifrost_app::host::{ControlCommand, LogOptions, init_tracing, run_resolved_daemon};
use bifrost_core::types::PeerPolicy;
use clap::{Args, Parser, Subcommand};
use igloo_shell_core::shell::{
    RelayProfile, SetupRequest, ShellPaths, add_relays, daemon_log_path, daemon_runtime_query,
    doctor_profile, export_profile, import_profile_from_files,
    import_profile_from_onboarding_package, import_profile_from_onboarding_value, list_profiles, load_relay_profiles,
    load_shell_config, read_daemon_metadata, read_profile, remove_profile, remove_relays,
    replace_relay_profile, resolve_profile_runtime, run_setup, set_default_relay_profile,
    clear_profile_peer_policy, set_profile_default_policy, set_profile_peer_policy,
    start_profile_daemon, stop_profile_daemon, test_relay_connectivity,
};
use igloo_shell_core::{e2e, invite, keygen, relay, tui};
use nostr::{FromBech32, Keys, PublicKey, SecretKey, ToBech32};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "igloo-shell")]
#[command(about = "Hard-cut FROSTR V2 shell", long_about = None)]
struct Cli {
    #[command(flatten)]
    trace: TraceArgs,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Args, Clone, Default)]
struct TraceArgs {
    #[arg(long, global = true)]
    trace: Option<String>,
    #[arg(long, global = true)]
    trace_level: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Setup(SetupArgs),
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommands,
    },
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },
    Invite {
        #[command(subcommand)]
        command: InviteCommands,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    Relays {
        #[command(subcommand)]
        command: RelayCommands,
    },
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
    },
    Tui {
        #[arg(long)]
        profile: Option<String>,
    },
    Dev {
        #[command(subcommand)]
        command: DevCommands,
    },
    #[command(hide = true, name = "__daemon-run")]
    DaemonRun(DaemonRunArgs),
}

#[derive(Debug, Subcommand)]
enum ProfileCommands {
    List,
    Show {
        profile_id: String,
    },
    Import(ProfileImportArgs),
    Export {
        profile_id: String,
        #[arg(long)]
        out_dir: String,
        #[arg(long)]
        vault_passphrase_env: Option<String>,
    },
    Remove {
        profile_id: String,
        #[arg(long)]
        yes: bool,
    },
    Doctor {
        profile_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum DaemonCommands {
    Start {
        #[arg(long)]
        profile: String,
    },
    Stop {
        #[arg(long)]
        profile: String,
    },
    Restart {
        #[arg(long)]
        profile: String,
    },
    Status {
        #[arg(long)]
        profile: Option<String>,
    },
    Logs {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommands {
    Status {
        #[arg(long)]
        profile: String,
    },
    Diagnostics {
        #[arg(long)]
        profile: String,
    },
    Readiness {
        #[arg(long)]
        profile: String,
    },
    ExplainReadiness {
        #[arg(long)]
        profile: String,
    },
    Ops {
        #[arg(long)]
        profile: String,
    },
    Sign {
        #[arg(long)]
        profile: String,
        message_hex32: String,
    },
    Ecdh {
        #[arg(long)]
        profile: String,
        pubkey_hex32: String,
    },
    WipeState {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PeerCommands {
    List {
        #[arg(long)]
        profile: String,
    },
    Ping {
        #[arg(long)]
        profile: String,
        peer_pubkey: String,
    },
    Onboard {
        #[arg(long)]
        profile: String,
        peer_pubkey: String,
        #[arg(long)]
        challenge_hex32: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum InviteCommands {
    Create {
        #[arg(long)]
        profile: String,
        #[arg(long = "relay")]
        relay_overrides: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        expires_in_secs: u64,
        #[arg(long)]
        label: Option<String>,
    },
    List {
        #[arg(long)]
        profile: String,
    },
    Show {
        #[arg(long)]
        profile: String,
        challenge_hex32: String,
    },
    Revoke {
        #[arg(long)]
        profile: String,
        challenge_hex32: String,
    },
    Assemble {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Accept {
        package: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Import {
        package_or_path: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long = "relay-profile")]
        relay_profile: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    Show {
        #[arg(long)]
        profile: String,
    },
    SetDefault {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        send: String,
        #[arg(long)]
        receive: String,
    },
    SetPeer {
        #[arg(long)]
        profile: String,
        peer_pubkey: String,
        #[arg(long)]
        send: String,
        #[arg(long)]
        receive: String,
    },
    ClearPeer {
        #[arg(long)]
        profile: String,
        peer_pubkey: String,
    },
}

#[derive(Debug, Subcommand)]
enum RelayCommands {
    List,
    Set(RelaySetArgs),
    Add(RelayMutateArgs),
    Remove(RelayMutateArgs),
    Default {
        profile_id: String,
    },
    Test {
        #[arg(long = "relay-profile")]
        relay_profile: Option<String>,
    },
}

#[derive(Debug, Args)]
struct RelaySetArgs {
    profile_id: String,
    #[arg(long)]
    label: Option<String>,
    relays: Vec<String>,
}

#[derive(Debug, Args)]
struct RelayMutateArgs {
    profile_id: String,
    relays: Vec<String>,
}

#[derive(Debug, Args)]
struct SetupArgs {
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    share: Option<String>,
    #[arg(long = "onboarding-package")]
    onboarding_package: Option<String>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long = "relay-profile")]
    relay_profile: Option<String>,
    #[arg(long = "relay")]
    relays: Vec<String>,
    #[arg(long)]
    vault_passphrase_env: Option<String>,
    #[arg(long)]
    onboarding_password_env: Option<String>,
    #[arg(long)]
    start_daemon: bool,
}

#[derive(Debug, Args)]
struct ProfileImportArgs {
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    share: Option<String>,
    #[arg(long = "onboarding-package")]
    onboarding_package: Option<String>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long = "relay-profile")]
    relay_profile: Option<String>,
    #[arg(long = "relay")]
    relays: Vec<String>,
    #[arg(long)]
    vault_passphrase_env: Option<String>,
    #[arg(long)]
    onboarding_password_env: Option<String>,
}

#[derive(Debug, Subcommand)]
enum KeyCommands {
    Convert {
        #[arg(long)]
        from: String,
        #[arg(long)]
        value: String,
    },
}

#[derive(Debug, Subcommand)]
enum DevCommands {
    Keygen {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Relay {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    E2eNode {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    E2eFull {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Args)]
struct DaemonRunArgs {
    #[arg(long)]
    profile: String,
    #[arg(long)]
    socket_path: String,
    #[arg(long)]
    token: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    configure_trace_env(&cli.trace)?;
    init_tracing(log_options(&cli.trace));
    let paths = ShellPaths::resolve()?;

    match cli.command {
        Commands::Setup(args) => handle_setup(&paths, args).await?,
        Commands::Profile { command } => handle_profile(&paths, command).await?,
        Commands::Daemon { command } => handle_daemon(&paths, command).await?,
        Commands::Runtime { command } => handle_runtime(&paths, command).await?,
        Commands::Peer { command } => handle_peer(&paths, command).await?,
        Commands::Invite { command } => handle_invite(&paths, command).await?,
        Commands::Policy { command } => handle_policy(&paths, command).await?,
        Commands::Relays { command } => handle_relays(&paths, command).await?,
        Commands::Keys { command } => handle_keys(command)?,
        Commands::Tui { profile } => {
            tui::run_tui(&paths, profile).await?;
        }
        Commands::Dev { command } => handle_dev(command).await?,
        Commands::DaemonRun(args) => handle_daemon_run(&paths, args).await?,
    }

    Ok(())
}

async fn handle_profile(paths: &ShellPaths, command: ProfileCommands) -> Result<()> {
    match command {
        ProfileCommands::List => {
            let profiles = list_profiles(paths)?;
            print_json(&profiles)
        }
        ProfileCommands::Show { profile_id } => {
            let profile = read_profile(paths, &profile_id)?;
            print_json(&profile)
        }
        ProfileCommands::Import(args) => handle_profile_import(paths, args).await,
        ProfileCommands::Export {
            profile_id,
            out_dir,
            vault_passphrase_env,
        } => {
            let result = export_profile(
                paths,
                &profile_id,
                std::path::Path::new(&out_dir),
                load_secret_from_env(vault_passphrase_env)?,
            )?;
            print_json(&result)
        }
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

async fn handle_setup(paths: &ShellPaths, args: SetupArgs) -> Result<()> {
    let relay_profile = ensure_relay_profile(paths, args.relay_profile, args.label.as_deref(), &args.relays)?;
    let result = run_setup(
        paths,
        SetupRequest {
            group_path: args.group.map(Into::into),
            share_path: args.share.map(Into::into),
            onboarding_package_path: args.onboarding_package.map(Into::into),
            label: args.label,
            relay_profile,
            vault_passphrase: load_secret_from_env(args.vault_passphrase_env)?,
            onboarding_password: load_secret_from_env(args.onboarding_password_env)?,
        },
        args.start_daemon,
    )
    .await?;
    print_json(&result)
}

async fn handle_profile_import(paths: &ShellPaths, args: ProfileImportArgs) -> Result<()> {
    let vault_passphrase = load_secret_from_env(args.vault_passphrase_env)?;
    let onboarding_password = load_secret_from_env(args.onboarding_password_env)?;
    let relay_profile = ensure_relay_profile(paths, args.relay_profile, args.label.as_deref(), &args.relays)?;
    let result = match (args.group, args.share, args.onboarding_package) {
        (Some(group), Some(share), None) => import_profile_from_files(
            paths,
            std::path::Path::new(&group),
            std::path::Path::new(&share),
            args.label,
            relay_profile,
            vault_passphrase,
        )?,
        (None, None, Some(package)) => {
            import_profile_from_onboarding_package(
                paths,
                std::path::Path::new(&package),
                args.label,
                relay_profile,
                vault_passphrase,
                onboarding_password,
            )
            .await?
        }
        _ => bail!("profile import requires either --group and --share, or --onboarding-package"),
    };

    print_json(&result)
}

async fn handle_daemon(paths: &ShellPaths, command: DaemonCommands) -> Result<()> {
    match command {
        DaemonCommands::Start { profile } => {
            let metadata = start_profile_daemon(paths, &profile).await?;
            print_json(&metadata)
        }
        DaemonCommands::Stop { profile } => {
            let result = stop_profile_daemon(paths, &profile).await?;
            print_json(&serde_json::json!({
                "stopped": true,
                "profile": profile,
                "result": result,
            }))
        }
        DaemonCommands::Restart { profile } => {
            let _ = stop_profile_daemon(paths, &profile).await;
            let metadata = start_profile_daemon(paths, &profile).await?;
            print_json(&serde_json::json!({
                "restarted": true,
                "profile": profile,
                "metadata": metadata,
            }))
        }
        DaemonCommands::Status { profile } => {
            if let Some(profile_id) = profile {
                let metadata = read_daemon_metadata(paths, &profile_id)?;
                let runtime = daemon_runtime_query(paths, &profile_id, ControlCommand::RuntimeMetadata).await?;
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

async fn handle_runtime(paths: &ShellPaths, command: RuntimeCommands) -> Result<()> {
    match command {
        RuntimeCommands::Status { profile } => {
            let status = daemon_runtime_query(paths, &profile, ControlCommand::RuntimeStatus).await?;
            print_json(&status)
        }
        RuntimeCommands::Diagnostics { profile } => {
            let diagnostics =
                daemon_runtime_query(paths, &profile, ControlCommand::RuntimeDiagnostics).await?;
            print_json(&diagnostics)
        }
        RuntimeCommands::Readiness { profile } => {
            let readiness = daemon_runtime_query(paths, &profile, ControlCommand::Readiness).await?;
            print_json(&readiness)
        }
        RuntimeCommands::ExplainReadiness { profile } => {
            let explanation =
                daemon_runtime_query(paths, &profile, ControlCommand::ReadinessExplain).await?;
            print_json(&explanation)
        }
        RuntimeCommands::Ops { profile } => {
            let metadata = daemon_runtime_query(paths, &profile, ControlCommand::RuntimeMetadata).await?;
            print_json(&serde_json::json!({
                "profile": profile,
                "runtime_metadata": metadata,
            }))
        }
        RuntimeCommands::Sign {
            profile,
            message_hex32,
        } => {
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::Sign {
                    message_hex32,
                    timeout_secs: None,
                },
            )
            .await?;
            print_json(&result)
        }
        RuntimeCommands::Ecdh {
            profile,
            pubkey_hex32,
        } => {
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::Ecdh {
                    pubkey_hex32,
                    timeout_secs: None,
                },
            )
            .await?;
            print_json(&result)
        }
        RuntimeCommands::WipeState { profile, yes } => {
            if !yes {
                bail!("runtime wipe-state requires --yes");
            }
            let result = daemon_runtime_query(paths, &profile, ControlCommand::WipeState).await?;
            print_json(&result)
        }
    }
}

async fn handle_peer(paths: &ShellPaths, command: PeerCommands) -> Result<()> {
    match command {
        PeerCommands::List { profile } => {
            let result = daemon_runtime_query(paths, &profile, ControlCommand::PeerStatus).await?;
            print_json(&result)
        }
        PeerCommands::Ping {
            profile,
            peer_pubkey,
        } => {
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::Ping {
                    peer: peer_pubkey,
                    timeout_secs: None,
                },
            )
            .await?;
            print_json(&result)
        }
        PeerCommands::Onboard {
            profile,
            peer_pubkey,
            challenge_hex32,
        } => {
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::Onboard {
                    peer: peer_pubkey,
                    timeout_secs: None,
                    challenge_hex32,
                },
            )
            .await?;
            print_json(&result)
        }
    }
}

async fn handle_invite(paths: &ShellPaths, command: InviteCommands) -> Result<()> {
    match command {
        InviteCommands::Assemble { args } => invite::run_invite_command(&with_subcommand("assemble", args)),
        InviteCommands::Accept { package, args } => {
            invite::run_invite_command(&with_leading_arg("accept", package, args))
        }
        InviteCommands::Import {
            package_or_path,
            label,
            relay_profile,
        } => {
            let result = if std::path::Path::new(&package_or_path).exists() {
                import_profile_from_onboarding_package(
                    paths,
                    std::path::Path::new(&package_or_path),
                    label,
                    relay_profile,
                    None,
                    None,
                )
                .await?
            } else {
                import_profile_from_onboarding_value(
                    paths,
                    &package_or_path,
                    label,
                    relay_profile,
                    None,
                    None,
                )
                .await?
            };
            print_json(&result)
        }
        InviteCommands::Create {
            profile,
            relay_overrides,
            expires_in_secs,
            label,
        } => {
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::InviteCreate {
                    relay_overrides,
                    expires_in_secs,
                    label,
                },
            )
            .await?;
            print_json(&result)
        }
        InviteCommands::List { profile } => {
            let result =
                daemon_runtime_query(paths, &profile, ControlCommand::InviteList).await?;
            print_json(&result)
        }
        InviteCommands::Show {
            profile,
            challenge_hex32,
        } => {
            let invites =
                daemon_runtime_query(paths, &profile, ControlCommand::InviteList).await?;
            let entries = invites
                .as_array()
                .ok_or_else(|| anyhow!("daemon returned invalid invite list"))?;
            let invite = entries
                .iter()
                .find(|entry| {
                    entry
                        .get("challenge_hex")
                        .and_then(serde_json::Value::as_str)
                        == Some(challenge_hex32.as_str())
                })
                .cloned()
                .ok_or_else(|| anyhow!("unknown invite challenge {challenge_hex32}"))?;
            print_json(&invite)
        }
        InviteCommands::Revoke {
            profile,
            challenge_hex32,
        } => {
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::InviteRevoke { challenge_hex32 },
            )
            .await?;
            print_json(&result)
        }
    }
}

async fn handle_policy(paths: &ShellPaths, command: PolicyCommands) -> Result<()> {
    match command {
        PolicyCommands::Show { profile } => {
            let result = daemon_runtime_query(paths, &profile, ControlCommand::Policies).await?;
            print_json(&result)
        }
        PolicyCommands::SetDefault {
            profile,
            send,
            receive,
        } => {
            let policy = send_receive_policy(&send, &receive)?;
            let profile = set_profile_default_policy(paths, &profile, policy)?;
            print_json(&serde_json::json!({
                "updated": true,
                "profile": profile.id,
                "restart_required": true,
                "manifest": profile,
            }))
        }
        PolicyCommands::SetPeer {
            profile,
            peer_pubkey,
            send,
            receive,
        } => {
            let policy = send_receive_policy(&send, &receive)?;
            let manifest = set_profile_peer_policy(paths, &profile, &peer_pubkey, policy.clone())?;
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::SetPolicy {
                    peer: peer_pubkey,
                    send: policy.request.sign,
                    receive: policy.respond.sign,
                },
            )
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
            let (manifest, policy) = clear_profile_peer_policy(paths, &profile, &peer_pubkey)?;
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::SetPolicy {
                    peer: peer_pubkey,
                    send: policy.request.sign,
                    receive: policy.respond.sign,
                },
            )
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

async fn handle_relays(paths: &ShellPaths, command: RelayCommands) -> Result<()> {
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

fn handle_keys(command: KeyCommands) -> Result<()> {
    match command {
        KeyCommands::Convert { from, value } => print_json(&convert_key(&from, &value)?),
    }
}

async fn handle_dev(command: DevCommands) -> Result<()> {
    match command {
        DevCommands::Keygen { args } => keygen::run_keygen_command(&args),
        DevCommands::Relay { args } => relay::run_relay_command(&args).await,
        DevCommands::E2eNode { args } => e2e::run_e2e_node_command(&args),
        DevCommands::E2eFull { args } => e2e::run_e2e_full_command(&args),
    }
}

async fn handle_daemon_run(paths: &ShellPaths, args: DaemonRunArgs) -> Result<()> {
    let (_profile, mut resolved) = resolve_profile_runtime(paths, &args.profile)?;
    resolved.state_path = std::path::PathBuf::from(&resolved.state_path);
    run_resolved_daemon(
        resolved,
        bifrost_app::host::DaemonTransportConfig {
            socket_path: args.socket_path.into(),
            token: args.token,
        },
    )
    .await
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => bail!("expected boolean value, got {value}"),
    }
}

fn send_receive_policy(send: &str, receive: &str) -> Result<PeerPolicy> {
    Ok(PeerPolicy::from_send_receive(
        parse_bool(send)?,
        parse_bool(receive)?,
    ))
}

fn convert_key(from: &str, value: &str) -> Result<serde_json::Value> {
    match from {
        "hex-private" => {
            let secret = SecretKey::from_hex(strip_hex_prefix(value))?;
            let public = Keys::new(secret.clone()).public_key();
            Ok(serde_json::json!({
                "input": {
                    "kind": "hex-private",
                    "value": secret.to_secret_hex(),
                },
                "outputs": {
                    "nsec": secret.to_bech32()?,
                    "public_hex": public.to_hex(),
                    "npub": public.to_bech32()?,
                }
            }))
        }
        "nsec" => {
            let secret = SecretKey::from_bech32(value)?;
            let public = Keys::new(secret.clone()).public_key();
            Ok(serde_json::json!({
                "input": {
                    "kind": "nsec",
                    "value": value,
                },
                "outputs": {
                    "private_hex": secret.to_secret_hex(),
                    "public_hex": public.to_hex(),
                    "npub": public.to_bech32()?,
                }
            }))
        }
        "hex-public" => {
            let public = PublicKey::from_hex(strip_hex_prefix(value))?;
            Ok(serde_json::json!({
                "input": {
                    "kind": "hex-public",
                    "value": public.to_hex(),
                },
                "outputs": {
                    "npub": public.to_bech32()?,
                }
            }))
        }
        "npub" => {
            let public = PublicKey::from_bech32(value)?;
            Ok(serde_json::json!({
                "input": {
                    "kind": "npub",
                    "value": value,
                },
                "outputs": {
                    "public_hex": public.to_hex(),
                }
            }))
        }
        _ => bail!("unsupported key input kind {from}; expected hex-private, nsec, hex-public, or npub"),
    }
}

fn strip_hex_prefix(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}

fn load_secret_from_env(env_name: Option<String>) -> Result<Option<String>> {
    match env_name {
        Some(name) => Ok(Some(
            std::env::var(&name)
                .map_err(|_| anyhow::anyhow!("missing env var {name}"))?,
        )),
        None => Ok(None),
    }
}

fn print_relay_profiles(paths: &ShellPaths) -> Result<()> {
    let config = load_shell_config(paths)?;
    let profiles = load_relay_profiles(paths)?;
    print_json(&serde_json::json!({
        "default_relay_profile_id": config.default_relay_profile_id,
        "profiles": profiles,
    }))
}

async fn follow_log_file(path: &Path) -> Result<()> {
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

fn ensure_relay_profile(
    paths: &ShellPaths,
    relay_profile: Option<String>,
    label: Option<&str>,
    relays: &[String],
) -> Result<Option<String>> {
    if relays.is_empty() {
        return Ok(relay_profile);
    }

    let profile_id = relay_profile
        .unwrap_or_else(|| format!("relay-{}", igloo_shell_core::shell::now_unix_secs()));
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

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn configure_trace_env(args: &TraceArgs) -> Result<()> {
    if std::env::var_os("RUST_LOG").is_some() {
        return Ok(());
    }
    let domains = args
        .trace
        .clone()
        .or_else(|| std::env::var("IGLOO_TRACE").ok())
        .unwrap_or_default();
    if domains.trim().is_empty() {
        return Ok(());
    }
    let level = args
        .trace_level
        .clone()
        .or_else(|| std::env::var("IGLOO_TRACE_LEVEL").ok())
        .unwrap_or_else(|| "debug".to_string());
    unsafe {
        std::env::set_var(
            "RUST_LOG",
            format!(
                "warn,igloo_shell_core={level},bifrost_app={level},bifrost_bridge_tokio={level},bifrost_signer={level}"
            ),
        );
    }
    Ok(())
}

fn log_options(args: &TraceArgs) -> LogOptions {
    let level = args
        .trace_level
        .clone()
        .or_else(|| std::env::var("IGLOO_TRACE_LEVEL").ok())
        .unwrap_or_else(|| "warn".to_string());
    match level.as_str() {
        "trace" | "debug" => LogOptions {
            verbose: false,
            debug: true,
        },
        "info" => LogOptions {
            verbose: true,
            debug: false,
        },
        _ => LogOptions {
            verbose: false,
            debug: false,
        },
    }
}

fn with_subcommand(name: &str, mut args: Vec<String>) -> Vec<String> {
    let mut full = vec![name.to_string()];
    full.append(&mut args);
    full
}

fn with_leading_arg(name: &str, first: String, mut rest: Vec<String>) -> Vec<String> {
    let mut full = vec![name.to_string(), first];
    full.append(&mut rest);
    full
}
