use std::fs;
use std::fs::File;
use std::io::{IsTerminal, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bifrost_app::host::{ControlCommand, LogOptions, init_tracing, run_resolved_daemon};
use bifrost_core::types::PolicyOverrideValue;
use clap::{Args, Parser, Subcommand, ValueEnum};
use crossterm::event::{Event, KeyCode, KeyEventKind, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use igloo_shell_core::shell::{
    DaemonMetadata, PolicyDirection, PolicyMethod, RelayProfile, RotationWorkspaceDocument,
    SetupRequest, ShellCheckKind, ShellPaths, add_relays,
    apply_rotation_update_from_bfonboard_value, check_profile_runtime, clear_profile_peer_policy,
    create_generated_keyset_draft, create_rotation_workspace, daemon_log_path,
    daemon_runtime_query, default_rotation_workspace_path, doctor_profile,
    export_generated_onboarding_package, export_profile, export_profile_as_bfonboard,
    export_profile_as_bfprofile, export_profile_as_bfshare, generate_rotation_workspace,
    import_generated_share, import_profile_from_bfprofile_value, import_profile_from_files,
    import_profile_from_onboarding_value, inspect_rotation_workspace, list_profiles,
    load_relay_profiles, load_rotation_workspace, load_shell_config, publish_profile_backup,
    read_daemon_metadata, read_profile, recover_profile_from_bfshare_value, remove_daemon_metadata,
    remove_profile, remove_relays, replace_relay_profile, resolve_profile_runtime, run_setup,
    set_default_relay_profile, set_profile_default_policy_override,
    set_profile_peer_policy_override, start_profile_daemon, start_profile_daemon_with_passphrase,
    stop_profile_daemon, test_relay_connectivity, validate_profile_unlock_with_passphrase,
};
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
    Import(ImportArgs),
    Export(ExportArgs),
    Recover(RecoverArgs),
    Onboard(OnboardArgs),
    RotateKey(RotateKeyArgs),
    RotateKeyset {
        #[command(subcommand)]
        command: RotateKeysetCommands,
    },
    Keygen(KeygenArgs),
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
    Check {
        #[command(subcommand)]
        command: CheckCommands,
    },
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
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
    #[command(hide = true, name = "__daemon-run")]
    DaemonRun(DaemonRunArgs),
}

#[derive(Debug, Subcommand)]
enum ProfileCommands {
    List,
    Show {
        profile_id: String,
    },
    Load(LoadArgs),
    Backup {
        profile_id: String,
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
enum RotateKeysetCommands {
    Init(RotateKeysetInitArgs),
    Show(RotateKeysetShowArgs),
    Generate(RotateKeysetGenerateArgs),
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
enum CheckCommands {
    Onboard {
        #[arg(long)]
        profile: String,
    },
    Sign {
        #[arg(long)]
        profile: String,
    },
    Ecdh {
        #[arg(long)]
        profile: String,
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
    },
}

#[derive(Debug, Args)]
struct OnboardArgs {
    package_or_path: String,
    #[arg(long, conflicts_with = "onboard_secret_file")]
    onboard_secret: Option<String>,
    #[arg(long, conflicts_with = "onboard_secret")]
    onboard_secret_file: Option<String>,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long, conflicts_with = "daemon", conflicts_with = "json")]
    start: bool,
    #[arg(long, conflicts_with = "start")]
    daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LoadArgs {
    profile_id: Option<String>,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long, conflicts_with = "daemon")]
    start: bool,
    #[arg(long, conflicts_with = "start")]
    daemon: bool,
}

#[derive(Debug, Args)]
struct ImportArgs {
    bfprofile_or_path: Option<String>,
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    share: Option<String>,
    #[arg(long = "relay-profile")]
    relay_profile: Option<String>,
    #[arg(long = "relay")]
    relays: Vec<String>,
    #[arg(long, conflicts_with = "package_secret_file")]
    package_secret: Option<String>,
    #[arg(long, conflicts_with = "package_secret")]
    package_secret_file: Option<String>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long, conflicts_with = "daemon", conflicts_with = "json")]
    start: bool,
    #[arg(long, conflicts_with = "start")]
    daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ExportArgs {
    profile_id: String,
    #[arg(long)]
    out: String,
    #[arg(long, default_value = "raw")]
    format: String,
    #[arg(long)]
    recipient_share: Option<String>,
    #[arg(long = "relay-url")]
    relay_urls: Vec<String>,
    #[arg(long)]
    vault_passphrase_env: Option<String>,
    #[arg(long)]
    package_password_env: Option<String>,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    bfshare_or_path: String,
    #[arg(long)]
    label: Option<String>,
    #[arg(long, conflicts_with = "package_secret_file")]
    package_secret: Option<String>,
    #[arg(long, conflicts_with = "package_secret")]
    package_secret_file: Option<String>,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long, conflicts_with = "daemon", conflicts_with = "json")]
    start: bool,
    #[arg(long, conflicts_with = "start")]
    daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RotateKeyArgs {
    package_or_path: String,
    #[arg(long)]
    profile: String,
    #[arg(long, conflicts_with = "onboard_secret_file")]
    onboard_secret: Option<String>,
    #[arg(long, conflicts_with = "onboard_secret")]
    onboard_secret_file: Option<String>,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long, conflicts_with = "daemon", conflicts_with = "json")]
    start: bool,
    #[arg(long, conflicts_with = "start")]
    daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RotateKeysetInitArgs {
    #[arg(long)]
    profile: String,
    #[arg(long)]
    threshold: u16,
    #[arg(long)]
    count: u16,
    #[arg(long)]
    workspace: Option<String>,
    #[arg(long = "source-bfshare")]
    source_bfshares: Vec<String>,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RotateKeysetShowArgs {
    #[arg(long)]
    workspace: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RotateKeysetGenerateArgs {
    #[arg(long)]
    workspace: String,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long, conflicts_with = "distribution_secret_file")]
    distribution_secret: Option<String>,
    #[arg(long, conflicts_with = "distribution_secret")]
    distribution_secret_file: Option<String>,
    #[arg(long, conflicts_with = "daemon", conflicts_with = "json")]
    start: bool,
    #[arg(long, conflicts_with = "start")]
    daemon: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct KeygenArgs {
    #[arg(long)]
    group_name: Option<String>,
    #[arg(long)]
    threshold: Option<u16>,
    #[arg(long)]
    count: Option<u16>,
    #[arg(long)]
    member_index: Option<u16>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long = "relay-url")]
    relay_urls: Vec<String>,
    #[arg(long, conflicts_with = "vault_secret_file")]
    vault_secret: Option<String>,
    #[arg(long, conflicts_with = "vault_secret")]
    vault_secret_file: Option<String>,
    #[arg(long, conflicts_with = "distribution_secret_file")]
    distribution_secret: Option<String>,
    #[arg(long, conflicts_with = "distribution_secret")]
    distribution_secret_file: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    Show {
        #[arg(long)]
        profile: String,
    },
    SetDefaultOverride {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        direction: CliPolicyDirection,
        #[arg(long)]
        method: CliPolicyMethod,
        #[arg(long)]
        value: CliPolicyValue,
    },
    SetPeerOverride {
        #[arg(long)]
        profile: String,
        peer_pubkey: String,
        #[arg(long)]
        direction: CliPolicyDirection,
        #[arg(long)]
        method: CliPolicyMethod,
        #[arg(long)]
        value: CliPolicyValue,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliPolicyDirection {
    Request,
    Respond,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliPolicyMethod {
    Ping,
    Onboard,
    Sign,
    Ecdh,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliPolicyValue {
    Unset,
    Allow,
    Deny,
}

#[derive(Debug, Args)]
struct SetupArgs {
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    share: Option<String>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long = "relay-profile")]
    relay_profile: Option<String>,
    #[arg(long = "relay")]
    relays: Vec<String>,
    #[arg(long)]
    vault_passphrase_env: Option<String>,
    #[arg(long)]
    start_daemon: bool,
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
        Commands::Import(args) => handle_import(&paths, args).await?,
        Commands::Export(args) => handle_export(&paths, args)?,
        Commands::Recover(args) => handle_recover(&paths, args).await?,
        Commands::Onboard(args) => handle_onboard(&paths, args).await?,
        Commands::RotateKey(args) => handle_rotate_key(&paths, args).await?,
        Commands::RotateKeyset { command } => handle_rotate_keyset(&paths, command).await?,
        Commands::Keygen(args) => handle_keygen(&paths, args).await?,
        Commands::Setup(args) => handle_setup(&paths, args).await?,
        Commands::Profile { command } => handle_profile(&paths, command).await?,
        Commands::Daemon { command } => handle_daemon(&paths, command).await?,
        Commands::Runtime { command } => handle_runtime(&paths, command).await?,
        Commands::Check { command } => handle_check(&paths, command).await?,
        Commands::Peer { command } => handle_peer(&paths, command).await?,
        Commands::Policy { command } => handle_policy(&paths, command).await?,
        Commands::Relays { command } => handle_relays(&paths, command).await?,
        Commands::Keys { command } => handle_keys(command)?,
        Commands::DaemonRun(args) => handle_daemon_run(&paths, args).await?,
    }

    Ok(())
}

async fn handle_rotate_keyset(paths: &ShellPaths, command: RotateKeysetCommands) -> Result<()> {
    match command {
        RotateKeysetCommands::Init(args) => handle_rotate_keyset_init(paths, args),
        RotateKeysetCommands::Show(args) => handle_rotate_keyset_show(paths, args),
        RotateKeysetCommands::Generate(args) => handle_rotate_keyset_generate(paths, args).await,
    }
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
        ProfileCommands::Load(args) => handle_load(paths, args).await,
        ProfileCommands::Backup {
            profile_id,
            vault_passphrase_env,
        } => {
            let result = publish_profile_backup(
                paths,
                &profile_id,
                load_secret_from_env(vault_passphrase_env)?,
            )
            .await?;
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

async fn handle_load(paths: &ShellPaths, args: LoadArgs) -> Result<()> {
    let mode = load_mode(&args);
    let profile_id = match args.profile_id {
        Some(profile_id) => {
            let _ = read_profile(paths, &profile_id)?;
            profile_id
        }
        None => prompt_select_profile(paths)?,
    };
    let vault_secret = resolve_secret_source_with(
        args.vault_secret,
        args.vault_secret_file,
        std::io::stdin().is_terminal(),
        "vault-secret",
        "profile load requires vault secret input; use --vault-secret / --vault-secret-file, or run on a TTY",
        prompt_load_vault_secret,
    )?;
    let profile = read_profile(paths, &profile_id)?;
    validate_profile_unlock_with_passphrase(paths, &profile_id, Some(vault_secret.clone()))?;
    match mode {
        LoadMode::StatusOnly => {
            print_profile_load_summary(paths, &profile)?;
            Ok(())
        }
        LoadMode::StartAttached => start_profile_attached(paths, &profile, vault_secret).await,
        LoadMode::StartBackground => {
            let (metadata, existing) =
                ensure_profile_daemon(paths, &profile.id, Some(vault_secret)).await?;
            print_daemon_started_summary(&profile, &metadata, existing);
            Ok(())
        }
    }
}

async fn handle_import(paths: &ShellPaths, args: ImportArgs) -> Result<()> {
    let label = resolve_profile_label(args.label)?;
    let vault_secret = resolve_secret_source_with(
        args.vault_secret,
        args.vault_secret_file,
        std::io::stdin().is_terminal(),
        "vault-secret",
        "import requires vault secret input; use --vault-secret / --vault-secret-file, or run on a TTY",
        prompt_vault_secret,
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
            Some(vault_secret.clone()),
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
                Some(vault_secret.clone()),
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
                ensure_profile_daemon(paths, &profile.id, Some(vault_secret.clone())).await?;
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
            return start_profile_attached(paths, profile, vault_secret).await;
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

fn handle_export(paths: &ShellPaths, args: ExportArgs) -> Result<()> {
    let vault_passphrase = load_secret_from_env(args.vault_passphrase_env)?;
    let result = match args.format.as_str() {
        "raw" => serde_json::to_value(export_profile(
            paths,
            &args.profile_id,
            std::path::Path::new(&args.out),
            vault_passphrase,
        )?)?,
        "bfprofile" => serde_json::to_value(export_profile_as_bfprofile(
            paths,
            &args.profile_id,
            require_env_secret(args.package_password_env, "package password")?,
            vault_passphrase,
            Some(std::path::Path::new(&args.out)),
        )?)?,
        "bfshare" => serde_json::to_value(export_profile_as_bfshare(
            paths,
            &args.profile_id,
            require_env_secret(args.package_password_env, "package password")?,
            vault_passphrase,
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
                vault_passphrase,
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

async fn handle_recover(paths: &ShellPaths, args: RecoverArgs) -> Result<()> {
    let package_raw = read_package_or_inline(&args.bfshare_or_path)?;
    let package_secret = resolve_package_secret(
        args.package_secret,
        args.package_secret_file,
        "recover requires package secret input; use --package-secret / --package-secret-file, or run on a TTY",
    )?;
    let vault_secret = resolve_secret_source_with(
        args.vault_secret,
        args.vault_secret_file,
        std::io::stdin().is_terminal(),
        "vault-secret",
        "recover requires vault secret input; use --vault-secret / --vault-secret-file, or run on a TTY",
        prompt_vault_secret,
    )?;
    let label = resolve_profile_label(args.label)?;
    let import = recover_profile_from_bfshare_value(
        paths,
        &package_raw,
        package_secret,
        Some(label),
        None,
        Some(vault_secret.clone()),
    )
    .await?;
    if let Ok(profile) = result_profile(&import) {
        if let Err(err) = publish_profile_backup(paths, &profile.id, None).await {
            eprintln!("warning: failed to publish encrypted profile backup: {err}");
        }
        let daemon = if args.daemon {
            let (metadata, existing) =
                ensure_profile_daemon(paths, &profile.id, Some(vault_secret.clone())).await?;
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
            return start_profile_attached(paths, profile, vault_secret).await;
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

async fn handle_rotate_key(paths: &ShellPaths, args: RotateKeyArgs) -> Result<()> {
    let package_raw = read_package_or_inline(&args.package_or_path)?;
    let vault_secret = resolve_vault_secret(args.vault_secret, args.vault_secret_file)?;
    let onboarding_secret = resolve_onboard_secret(args.onboard_secret, args.onboard_secret_file)?;
    let target = read_profile(paths, &args.profile)?;
    let old_profile_id = target.id.clone();

    let import = apply_rotation_update_from_bfonboard_value(
        paths,
        &old_profile_id,
        &package_raw,
        onboarding_secret,
        Some(vault_secret.clone()),
    )
    .await?;

    let profile = result_profile(&import)?;
    let new_profile_id = profile.id.clone();

    if let Err(err) = publish_profile_backup(paths, &new_profile_id, None).await {
        eprintln!("warning: failed to publish encrypted profile backup: {err}");
    }

    let daemon = if args.daemon {
        let (metadata, existing) =
            ensure_profile_daemon(paths, &new_profile_id, Some(vault_secret.clone())).await?;
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
        return start_profile_attached(paths, profile, vault_secret).await;
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
    let vault_secret = resolve_secret_source_with(
        args.vault_secret,
        args.vault_secret_file,
        stdin_is_terminal,
        "vault-secret",
        "rotate-keyset init requires vault secret input; use --vault-secret / --vault-secret-file, or run on a TTY",
        prompt_load_vault_secret,
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
        Some(vault_secret),
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
    let vault_secret = resolve_secret_source_with(
        args.vault_secret,
        args.vault_secret_file,
        stdin_is_terminal,
        "vault-secret",
        "rotate-keyset generate requires vault secret input; use --vault-secret / --vault-secret-file, or run on a TTY",
        prompt_load_vault_secret,
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
            prompt_distribution_secret,
        )?)
    } else {
        None
    };

    let result = generate_rotation_workspace(
        paths,
        &workspace_root,
        source_passwords,
        Some(vault_secret.clone()),
        distribution_secret,
    )
    .await?;

    let daemon = if args.daemon {
        let (metadata, existing) =
            ensure_profile_daemon(paths, &result.profile.id, Some(vault_secret.clone())).await?;
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
        return start_profile_attached(paths, &result.profile, vault_secret).await;
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

async fn handle_keygen(paths: &ShellPaths, args: KeygenArgs) -> Result<()> {
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
    let vault_secret = resolve_secret_source_with(
        args.vault_secret,
        args.vault_secret_file,
        stdin_is_terminal,
        "vault-secret",
        "keygen requires vault secret input; use --vault-secret / --vault-secret-file, or run on a TTY",
        prompt_vault_secret,
    )?;
    let distribution_secret = resolve_secret_source_with(
        args.distribution_secret,
        args.distribution_secret_file,
        stdin_is_terminal,
        "distribution-secret",
        "keygen requires onboarding package secret input; use --distribution-secret / --distribution-secret-file, or run on a TTY",
        prompt_distribution_secret,
    )?;
    let import = import_generated_share(
        paths,
        &draft,
        member_index,
        label,
        relay_urls.clone(),
        Some(vault_secret.clone()),
    )?;
    let profile = result_profile(&import)?.clone();
    if let Err(err) = publish_profile_backup(paths, &profile.id, None).await {
        eprintln!("warning: failed to publish encrypted profile backup: {err}");
    }
    let export_root = paths
        .state_dir
        .join("generated-onboarding")
        .join(&profile.id);
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

async fn handle_setup(paths: &ShellPaths, args: SetupArgs) -> Result<()> {
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
            vault_passphrase: load_secret_from_env(args.vault_passphrase_env)?,
            onboarding_password: None,
        },
        args.start_daemon,
    )
    .await?;
    print_json(&result)
}

async fn handle_onboard(paths: &ShellPaths, args: OnboardArgs) -> Result<()> {
    let package_raw = read_package_or_inline(&args.package_or_path)?;
    let label = resolve_profile_label(args.label)?;
    let onboarding_secret = resolve_onboard_secret(args.onboard_secret, args.onboard_secret_file)?;
    let vault_secret = resolve_vault_secret(args.vault_secret, args.vault_secret_file)?;
    let import = import_profile_from_onboarding_value(
        paths,
        &package_raw,
        Some(label),
        None,
        Some(vault_secret.clone()),
        Some(onboarding_secret),
    )
    .await?;
    let profile = result_profile(&import)?;
    let profile_id = profile.id.clone();
    let daemon = if args.daemon {
        let (metadata, existing) =
            ensure_profile_daemon(paths, &profile_id, Some(vault_secret.clone())).await?;
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
            return start_profile_attached(paths, profile, vault_secret).await;
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
                let runtime =
                    daemon_runtime_query(paths, &profile_id, ControlCommand::RuntimeMetadata)
                        .await?;
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
            let status =
                daemon_runtime_query(paths, &profile, ControlCommand::RuntimeStatus).await?;
            print_json(&status)
        }
        RuntimeCommands::Diagnostics { profile } => {
            let diagnostics =
                daemon_runtime_query(paths, &profile, ControlCommand::RuntimeDiagnostics).await?;
            print_json(&diagnostics)
        }
        RuntimeCommands::Ops { profile } => {
            let metadata =
                daemon_runtime_query(paths, &profile, ControlCommand::RuntimeMetadata).await?;
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

async fn handle_check(paths: &ShellPaths, command: CheckCommands) -> Result<()> {
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
        } => {
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::Onboard {
                    peer: peer_pubkey,
                    timeout_secs: None,
                },
            )
            .await?;
            print_json(&result)
        }
    }
}

async fn handle_policy(paths: &ShellPaths, command: PolicyCommands) -> Result<()> {
    match command {
        PolicyCommands::Show { profile } => {
            let result =
                daemon_runtime_query(paths, &profile, ControlCommand::RuntimeStatus).await?;
            let policies = result
                .get("peer_permission_states")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            print_json(&policies)
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
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::SetPolicyOverride {
                    peer: peer_pubkey,
                    policy_override_json: serde_json::to_string(&effective_override)
                        .context("serialize policy override")?,
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
            let (manifest, effective_override) =
                clear_profile_peer_policy(paths, &profile, &peer_pubkey)?;
            let result = daemon_runtime_query(
                paths,
                &profile,
                ControlCommand::SetPolicyOverride {
                    peer: peer_pubkey,
                    policy_override_json: serde_json::to_string(&effective_override)
                        .context("serialize policy override")?,
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

fn resolve_onboard_secret(value: Option<String>, file: Option<String>) -> Result<String> {
    resolve_secret_source_with(
        value,
        file,
        std::io::stdin().is_terminal(),
        "onboard-secret",
        "onboard requires onboarding secret input; use --onboard-secret / --onboard-secret-file, or run on a TTY",
        prompt_onboarding_secret,
    )
}

fn resolve_profile_label(value: Option<String>) -> Result<String> {
    resolve_profile_label_with(value, std::io::stdin().is_terminal(), prompt_profile_label)
}

fn resolve_profile_label_with<F>(
    value: Option<String>,
    stdin_is_terminal: bool,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        Some(_) => bail!("label cannot be empty"),
        None if stdin_is_terminal => prompt(),
        None => bail!("onboard requires --label when stdin is not a TTY"),
    }
}

fn resolve_vault_secret(value: Option<String>, file: Option<String>) -> Result<String> {
    resolve_secret_source_with(
        value,
        file,
        std::io::stdin().is_terminal(),
        "vault-secret",
        "onboard requires vault secret input; use --vault-secret / --vault-secret-file, or run on a TTY",
        prompt_vault_secret,
    )
}

fn resolve_package_secret(
    value: Option<String>,
    file: Option<String>,
    missing_message: &str,
) -> Result<String> {
    resolve_secret_source_with(
        value,
        file,
        std::io::stdin().is_terminal(),
        "package-secret",
        missing_message,
        prompt_package_secret,
    )
}

fn resolve_required_text<F>(
    value: Option<String>,
    stdin_is_terminal: bool,
    missing_message: &str,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        Some(_) => bail!("value cannot be empty"),
        None if stdin_is_terminal => prompt(),
        None => bail!("{missing_message}"),
    }
}

fn resolve_u16_input<F>(
    value: Option<u16>,
    stdin_is_terminal: bool,
    label: &str,
    missing_message: &str,
    prompt: F,
) -> Result<u16>
where
    F: FnOnce() -> Result<u16>,
{
    match value {
        Some(value) if value > 0 => Ok(value),
        Some(_) => bail!("{label} must be greater than zero"),
        None if stdin_is_terminal => prompt(),
        None => bail!("{missing_message}"),
    }
}

fn resolve_member_index(
    value: Option<u16>,
    draft: &igloo_shell_core::shell::GeneratedKeysetDraft,
    stdin_is_terminal: bool,
    missing_message: &str,
) -> Result<u16> {
    match value {
        Some(member_idx) => validate_member_index(draft, member_idx),
        None if stdin_is_terminal => prompt_member_index(draft),
        None => bail!("{missing_message}"),
    }
}

fn validate_member_index(
    draft: &igloo_shell_core::shell::GeneratedKeysetDraft,
    member_idx: u16,
) -> Result<u16> {
    if draft
        .shares
        .iter()
        .any(|share| share.member_idx == member_idx)
    {
        return Ok(member_idx);
    }
    bail!("member index {member_idx} is not available in this generated keyset")
}

fn resolve_keygen_relays(relay_urls: Vec<String>, stdin_is_terminal: bool) -> Result<Vec<String>> {
    if !relay_urls.is_empty() {
        return Ok(relay_urls);
    }
    if stdin_is_terminal {
        return prompt_relay_urls();
    }
    bail!("keygen requires at least one --relay-url when stdin is not a TTY")
}

fn resolve_secret_source_with<F>(
    value: Option<String>,
    file: Option<String>,
    stdin_is_terminal: bool,
    secret_label: &str,
    missing_message: &str,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match (value, file) {
        (Some(value), None) => {
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(value)
        }
        (None, Some(path)) => {
            let value = fs::read_to_string(&path)
                .with_context(|| format!("read {secret_label} file {path}"))?
                .trim_end()
                .to_string();
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(value)
        }
        (None, None) if stdin_is_terminal => {
            let value = prompt()?.trim_end().to_string();
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(value)
        }
        (None, None) => bail!("{missing_message}"),
        (Some(_), Some(_)) => unreachable!("clap enforces secret source conflicts"),
    }
}

fn resolve_rotation_source_passwords(
    document: &RotationWorkspaceDocument,
    stdin_is_terminal: bool,
) -> Result<Vec<String>> {
    document
        .source_packages
        .iter()
        .map(|source| {
            let package_secret = load_secret_from_env(source.package_secret_env.clone())?;
            resolve_secret_source_with(
                package_secret,
                source.package_secret_file.clone(),
                stdin_is_terminal,
                "package-secret",
                &format!(
                    "rotate-keyset generate requires a source package secret for {}; set package_secret_env/package_secret_file in the workspace or run on a TTY",
                    source.package_path
                ),
                || prompt_rotation_source_package_secret(&source.package_path),
            )
        })
        .collect()
}

fn read_package_or_inline(package_or_path: &str) -> Result<String> {
    let path = Path::new(package_or_path);
    if path.exists() {
        return Ok(fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?
            .trim()
            .to_string());
    }
    Ok(package_or_path.to_string())
}

fn prompt_hidden_secret(lines: &[&str], prompt: &str) -> Result<String> {
    for line in lines {
        println!("{line}");
    }
    print!("{prompt}: ");
    std::io::Write::flush(&mut std::io::stdout()).context("flush secret prompt")?;

    enable_raw_mode().context("enable raw mode for secret prompt")?;
    let mut password = String::new();
    let result: Result<()> = loop {
        match read().context("read secret input")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char(c) => password.push(c),
                KeyCode::Backspace => {
                    password.pop();
                }
                _ => {}
            },
            _ => {}
        }
    };
    let disable_result = disable_raw_mode().context("disable raw mode for secret prompt");
    println!();
    result?;
    disable_result?;

    if password.is_empty() {
        bail!("secret input cannot be empty");
    }
    Ok(password)
}

fn prompt_profile_label() -> Result<String> {
    loop {
        println!("Choose a name for this profile before entering any secrets.");
        println!("This label will be shown in profile selection and status output.");
        print!("Profile name: ");
        std::io::Write::flush(&mut std::io::stdout()).context("flush profile name prompt")?;

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("read profile name")?;
        let value = input.trim().to_string();
        if !value.is_empty() {
            return Ok(value);
        }
        println!("Profile name cannot be empty.");
    }
}

fn prompt_onboarding_secret() -> Result<String> {
    prompt_hidden_secret(
        &[
            "This onboarding package is encrypted.",
            "Type the onboarding secret now to decrypt the package input.",
        ],
        "Onboarding secret",
    )
}

fn prompt_vault_secret() -> Result<String> {
    loop {
        let secret = prompt_hidden_secret(
            &[
                "This import will store secrets in your local igloo-shell vault.",
                "Type a vault secret now to encrypt imported local secrets on this device.",
            ],
            "Vault secret",
        )?;
        let confirm = prompt_hidden_secret(
            &["Retype the vault secret to confirm your input."],
            "Confirm vault secret",
        )?;
        if secret == confirm {
            return Ok(secret);
        }
        println!("Vault secrets did not match. Please try again.");
    }
}

fn prompt_load_vault_secret() -> Result<String> {
    prompt_hidden_secret(
        &[
            "Type the vault secret for the selected profile now.",
            "igloo-shell will use it to unlock the profile on this device.",
        ],
        "Vault secret",
    )
}

fn prompt_package_secret() -> Result<String> {
    prompt_hidden_secret(
        &[
            "This package is encrypted.",
            "Type the package secret now to continue the import or recovery flow.",
        ],
        "Package secret",
    )
}

fn prompt_distribution_secret() -> Result<String> {
    prompt_hidden_secret(
        &[
            "The remaining generated shares will be written as onboarding packages.",
            "Type the onboarding secret that should encrypt those packages.",
        ],
        "Onboarding package secret",
    )
}

fn prompt_rotation_source_package_secret(package_path: &str) -> Result<String> {
    prompt_hidden_secret(
        &[
            "This rotation source package is encrypted.",
            "Type the package secret now to continue the rotation workflow.",
            package_path,
        ],
        "Package secret",
    )
}

fn prompt_group_name() -> Result<String> {
    prompt_line(
        &[
            "Create a new local group.",
            "Type the group name that should be used to identify this group and its shares.",
        ],
        "Group name",
    )
}

fn prompt_threshold() -> Result<u16> {
    prompt_u16(
        &["Type the signing threshold for the new keyset."],
        "Threshold",
    )
}

fn prompt_count() -> Result<u16> {
    prompt_u16(
        &["Type the total member count for the new keyset."],
        "Member count",
    )
}

fn prompt_relay_urls() -> Result<Vec<String>> {
    loop {
        let raw = prompt_line(
            &[
                "Type one or more relay URLs for this generated profile.",
                "Use commas to separate multiple relay URLs.",
            ],
            "Relay URLs",
        )?;
        let relays = raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !relays.is_empty() {
            return Ok(relays);
        }
        println!("At least one relay URL is required.");
    }
}

fn prompt_member_index(draft: &igloo_shell_core::shell::GeneratedKeysetDraft) -> Result<u16> {
    println!("Select which generated share should stay on this device:");
    for share in &draft.shares {
        println!("  {}: {}", share.member_idx, share.label);
    }
    loop {
        let member_idx = prompt_u16(&[], "Local member index")?;
        match validate_member_index(draft, member_idx) {
            Ok(member_idx) => return Ok(member_idx),
            Err(err) => println!("{err}"),
        }
    }
}

fn prompt_line(lines: &[&str], prompt: &str) -> Result<String> {
    for line in lines {
        println!("{line}");
    }
    print!("{prompt}: ");
    std::io::Write::flush(&mut std::io::stdout()).context("flush prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read prompt input")?;
    let value = input.trim().to_string();
    if value.is_empty() {
        bail!("{prompt} cannot be empty");
    }
    Ok(value)
}

fn prompt_u16(lines: &[&str], prompt: &str) -> Result<u16> {
    loop {
        match prompt_line(lines, prompt)?.parse::<u16>() {
            Ok(value) if value > 0 => return Ok(value),
            Ok(_) => println!("{prompt} must be greater than zero."),
            Err(_) => println!("{prompt} must be a positive integer."),
        }
    }
}

fn prompt_select_profile(paths: &ShellPaths) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("profile load requires a profile id when stdin is not a TTY");
    }
    let profiles = list_profiles(paths)?;
    if profiles.is_empty() {
        bail!("no profiles found; use igloo-shell onboard, import, recover, or keygen first");
    }
    println!("Select a profile to load:");
    for (index, profile) in profiles.iter().enumerate() {
        println!(
            "  {}: {} ({})",
            index + 1,
            profile.label,
            &profile.id[..profile.id.len().min(8)]
        );
    }
    loop {
        let selection = prompt_u16(&[], "Profile number")?;
        let index = usize::from(selection.saturating_sub(1));
        if let Some(profile) = profiles.get(index) {
            return Ok(profile.id.clone());
        }
        println!("Profile number {selection} is not valid.");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadMode {
    StatusOnly,
    StartAttached,
    StartBackground,
}

fn load_mode(args: &LoadArgs) -> LoadMode {
    if args.start {
        LoadMode::StartAttached
    } else if args.daemon {
        LoadMode::StartBackground
    } else {
        LoadMode::StatusOnly
    }
}

fn short_profile_id(profile_id: &str) -> &str {
    &profile_id[..profile_id.len().min(8)]
}

fn print_profile_ready_summary(prefix: &str, profile: &igloo_shell_core::shell::ProfileManifest) {
    println!(
        "{prefix} Profile \"{}\" ({}) is ready.",
        profile.label,
        short_profile_id(&profile.id)
    );
}

fn print_profile_next_commands(profile_id: &str) {
    println!("Next commands:");
    println!("  igloo-shell profile load {profile_id}");
    println!("  igloo-shell profile load {profile_id} --start");
    println!("  igloo-shell profile load {profile_id} --daemon");
    println!("  igloo-shell daemon status --profile {profile_id}");
}

fn print_rotation_workspace_status(status: &igloo_shell_core::shell::RotationWorkspaceStatus) {
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

fn print_rotation_generated_packages(result: &igloo_shell_core::shell::RotationGenerateResult) {
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

fn print_running_profile_commands(profile_id: &str) {
    println!("Useful status commands:");
    println!("  igloo-shell daemon status --profile {profile_id}");
    println!("  igloo-shell runtime status --profile {profile_id}");
    println!("  igloo-shell peer list --profile {profile_id}");
    println!("  igloo-shell policy show --profile {profile_id}");
    println!("  igloo-shell daemon logs --profile {profile_id} --follow");
}

fn print_daemon_started_summary(
    profile: &igloo_shell_core::shell::ProfileManifest,
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

fn print_profile_load_summary(
    paths: &ShellPaths,
    profile: &igloo_shell_core::shell::ProfileManifest,
) -> Result<()> {
    println!(
        "Profile loaded: \"{}\" ({})",
        profile.label,
        short_profile_id(&profile.id)
    );
    println!("Vault unlock succeeded.");
    let daemon_state = if read_daemon_metadata(paths, &profile.id).is_ok() {
        "running or recorded"
    } else {
        "not running"
    };
    println!("Daemon: {daemon_state}");
    print_profile_next_commands(&profile.id);
    Ok(())
}

async fn ensure_profile_daemon(
    paths: &ShellPaths,
    profile_id: &str,
    vault_secret: Option<String>,
) -> Result<(DaemonMetadata, bool)> {
    if let Ok(metadata) = read_daemon_metadata(paths, profile_id) {
        if daemon_runtime_query(paths, profile_id, ControlCommand::RuntimeMetadata)
            .await
            .is_ok()
        {
            return Ok((metadata, true));
        }
        let _ = remove_daemon_metadata(paths, profile_id);
    }

    let metadata = if let Some(secret) = vault_secret {
        start_profile_daemon_with_passphrase(paths, profile_id, Some(secret)).await?
    } else {
        start_profile_daemon(paths, profile_id).await?
    };
    Ok((metadata, false))
}

async fn start_profile_attached(
    paths: &ShellPaths,
    profile: &igloo_shell_core::shell::ProfileManifest,
    vault_secret: String,
) -> Result<()> {
    let (metadata, existing) =
        ensure_profile_daemon(paths, &profile.id, Some(vault_secret)).await?;
    print_daemon_started_summary(profile, &metadata, existing);
    println!("Streaming daemon log. Press Ctrl-C to exit.");
    follow_log_file(Path::new(&metadata.log_path)).await
}

fn result_profile(
    result: &igloo_shell_core::shell::ProfileImportResult,
) -> Result<&igloo_shell_core::shell::ProfileManifest> {
    match result {
        igloo_shell_core::shell::ProfileImportResult::ProfileCreated { profile, .. } => Ok(profile),
        igloo_shell_core::shell::ProfileImportResult::OnboardingStaged { .. } => {
            bail!("onboarding did not create a profile")
        }
    }
}

fn policy_direction(value: CliPolicyDirection) -> PolicyDirection {
    match value {
        CliPolicyDirection::Request => PolicyDirection::Request,
        CliPolicyDirection::Respond => PolicyDirection::Respond,
    }
}

fn policy_method(value: CliPolicyMethod) -> PolicyMethod {
    match value {
        CliPolicyMethod::Ping => PolicyMethod::Ping,
        CliPolicyMethod::Onboard => PolicyMethod::Onboard,
        CliPolicyMethod::Sign => PolicyMethod::Sign,
        CliPolicyMethod::Ecdh => PolicyMethod::Ecdh,
    }
}

fn policy_value(value: CliPolicyValue) -> PolicyOverrideValue {
    match value {
        CliPolicyValue::Unset => PolicyOverrideValue::Unset,
        CliPolicyValue::Allow => PolicyOverrideValue::Allow,
        CliPolicyValue::Deny => PolicyOverrideValue::Deny,
    }
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
        _ => bail!(
            "unsupported key input kind {from}; expected hex-private, nsec, hex-public, or npub"
        ),
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
            std::env::var(&name).map_err(|_| anyhow::anyhow!("missing env var {name}"))?,
        )),
        None => Ok(None),
    }
}

fn require_env_secret(env_name: Option<String>, label: &str) -> Result<String> {
    load_secret_from_env(env_name)?
        .ok_or_else(|| anyhow!("{label} must be provided through an environment variable"))
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, resolve_profile_label_with, resolve_secret_source_with};

    #[test]
    fn secret_source_prefers_flag_value() {
        let value = resolve_secret_source_with(
            Some("secret".to_string()),
            None,
            false,
            "onboard-secret",
            "missing",
            || panic!("prompt should not be used"),
        )
        .expect("secret");
        assert_eq!(value, "secret");
    }

    #[test]
    fn secret_source_uses_prompt_on_tty() {
        let value = resolve_secret_source_with(None, None, true, "vault-secret", "missing", || {
            Ok("prompt-pass\n".to_string())
        })
        .expect("prompt secret");
        assert_eq!(value, "prompt-pass");
    }

    #[test]
    fn secret_source_rejects_non_tty_without_flags() {
        let err =
            resolve_secret_source_with(None, None, false, "vault-secret", "missing flags", || {
                panic!("prompt should not be used")
            })
            .expect_err("non-tty should fail");
        assert!(err.to_string().contains("missing flags"));
    }

    #[test]
    fn profile_label_uses_prompt_on_tty() {
        let label = resolve_profile_label_with(None, true, || Ok("Alice".to_string()))
            .expect("profile label");
        assert_eq!(label, "Alice");
    }

    #[test]
    fn profile_label_requires_flag_on_non_tty() {
        let err = resolve_profile_label_with(None, false, || panic!("prompt should not be used"))
            .expect_err("missing label should fail");
        assert!(err.to_string().contains("--label"));
    }

    #[test]
    fn load_cli_rejects_conflicting_daemon_flags() {
        let err = Cli::try_parse_from([
            "igloo-shell",
            "profile",
            "load",
            "demo",
            "--start",
            "--daemon",
        ])
        .expect_err("conflicting flags should fail");
        assert!(err.to_string().contains("--start"));
    }

    #[test]
    fn onboard_cli_accepts_start_flag() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "onboard",
            "package",
            "--label",
            "demo",
            "--onboard-secret",
            "invite",
            "--vault-secret",
            "vault",
            "--start",
        ])
        .expect("start flag should parse");
        match cli.command {
            super::Commands::Onboard(args) => assert!(args.start),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn import_cli_accepts_start_flag() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "import",
            "package",
            "--label",
            "demo",
            "--package-secret",
            "pkg",
            "--vault-secret",
            "vault",
            "--start",
        ])
        .expect("start flag should parse");
        match cli.command {
            super::Commands::Import(args) => assert!(args.start),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn recover_cli_accepts_start_flag() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "recover",
            "package",
            "--label",
            "demo",
            "--package-secret",
            "pkg",
            "--vault-secret",
            "vault",
            "--start",
        ])
        .expect("start flag should parse");
        match cli.command {
            super::Commands::Recover(args) => assert!(args.start),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn recover_cli_rejects_replace_profile_flag() {
        let err = Cli::try_parse_from([
            "igloo-shell",
            "recover",
            "package",
            "--label",
            "demo",
            "--package-secret",
            "pkg",
            "--vault-secret",
            "vault",
            "--replace-profile",
            "old-profile",
        ])
        .expect_err("removed flag should fail");
        assert!(err.to_string().contains("--replace-profile"));
    }

    #[test]
    fn rotate_key_cli_accepts_start_flag() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "rotate-key",
            "package",
            "--profile",
            "old-profile",
            "--onboard-secret",
            "invite",
            "--vault-secret",
            "vault",
            "--start",
        ])
        .expect("start flag should parse");
        match cli.command {
            super::Commands::RotateKey(args) => assert!(args.start),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn onboard_cli_rejects_start_with_json() {
        let err = Cli::try_parse_from([
            "igloo-shell",
            "onboard",
            "package",
            "--label",
            "demo",
            "--onboard-secret",
            "invite",
            "--vault-secret",
            "vault",
            "--start",
            "--json",
        ])
        .expect_err("conflicting flags should fail");
        assert!(err.to_string().contains("--start"));
    }

    #[test]
    fn rotate_key_cli_rejects_start_with_json() {
        let err = Cli::try_parse_from([
            "igloo-shell",
            "rotate-key",
            "package",
            "--profile",
            "old-profile",
            "--onboard-secret",
            "invite",
            "--vault-secret",
            "vault",
            "--start",
            "--json",
        ])
        .expect_err("conflicting flags should fail");
        assert!(err.to_string().contains("--start"));
    }

    #[test]
    fn rotate_keyset_init_cli_parses() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "rotate-keyset",
            "init",
            "--profile",
            "source-profile",
            "--threshold",
            "2",
            "--count",
            "4",
            "--workspace",
            "/tmp/rotation-workspace",
            "--source-bfshare",
            "/tmp/alice.bfshare",
            "--vault-secret",
            "vault",
            "--json",
        ])
        .expect("rotate-keyset init should parse");
        match cli.command {
            super::Commands::RotateKeyset { command } => match command {
                super::RotateKeysetCommands::Init(args) => {
                    assert_eq!(args.profile, "source-profile");
                    assert_eq!(args.threshold, 2);
                    assert_eq!(args.count, 4);
                    assert_eq!(args.source_bfshares.len(), 1);
                }
                other => panic!("unexpected rotate-keyset command: {other:?}"),
            },
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rotate_keyset_show_cli_parses() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "rotate-keyset",
            "show",
            "--workspace",
            "/tmp/rotation-workspace",
            "--json",
        ])
        .expect("rotate-keyset show should parse");
        match cli.command {
            super::Commands::RotateKeyset { command } => match command {
                super::RotateKeysetCommands::Show(args) => {
                    assert_eq!(args.workspace, "/tmp/rotation-workspace");
                    assert!(args.json);
                }
                other => panic!("unexpected rotate-keyset command: {other:?}"),
            },
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rotate_keyset_generate_cli_accepts_start_flag() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "rotate-keyset",
            "generate",
            "--workspace",
            "/tmp/rotation-workspace",
            "--vault-secret",
            "vault",
            "--distribution-secret",
            "dist",
            "--start",
        ])
        .expect("rotate-keyset generate should parse");
        match cli.command {
            super::Commands::RotateKeyset { command } => match command {
                super::RotateKeysetCommands::Generate(args) => assert!(args.start),
                other => panic!("unexpected rotate-keyset command: {other:?}"),
            },
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rotate_keyset_generate_rejects_start_with_json() {
        let err = Cli::try_parse_from([
            "igloo-shell",
            "rotate-keyset",
            "generate",
            "--workspace",
            "/tmp/rotation-workspace",
            "--vault-secret",
            "vault",
            "--distribution-secret",
            "dist",
            "--start",
            "--json",
        ])
        .expect_err("conflicting flags should fail");
        assert!(err.to_string().contains("--start"));
    }
}
