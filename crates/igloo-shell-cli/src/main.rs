use std::fs;
use std::fs::File;
use std::io::{IsTerminal, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bifrost_app::host::{LogOptions, init_tracing};
use bifrost_core::types::PolicyOverrideValue;
use bifrost_profile::{
    ProfilePaths as ShellPaths, export_profile, export_profile_as_bfonboard,
    export_profile_as_bfprofile, export_profile_as_bfshare, import_profile_from_bfprofile_value,
    import_profile_from_files,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use crossterm::event::{Event, KeyCode, KeyEventKind, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use igloo_shell_core::shell::{
    PolicyDirection, PolicyMethod, RelayProfile, RotationWorkspaceDocument, SetupRequest,
    ShellCheckKind, add_relays,
};
use igloo_shell_core::shell::{
    apply_rotation_update_from_bfonboard_value, check_profile_runtime, clear_profile_peer_policy,
    create_generated_keyset_draft, create_rotation_workspace, daemon_ecdh, daemon_log_path,
    daemon_onboard, daemon_peer_status, daemon_ping, daemon_runtime_diagnostics,
    daemon_runtime_metadata, daemon_runtime_status, daemon_set_policy_override, daemon_sign,
    daemon_wipe_state, default_rotation_workspace_path, doctor_profile,
    export_generated_onboarding_package, generate_rotation_workspace, import_generated_share,
    import_profile_from_onboarding_value, inspect_rotation_workspace, list_profiles,
    load_relay_profiles, load_rotation_workspace, load_shell_config, read_daemon_metadata,
    read_profile, recover_group_secret_from_profile_and_shares, remove_daemon_metadata,
    remove_profile, remove_relays, replace_relay_profile, run_setup, set_default_relay_profile,
    set_profile_default_policy_override, set_profile_peer_policy_override, start_profile_daemon,
    start_profile_daemon_with_passphrase, stop_profile_daemon, stop_profile_daemon_typed,
    test_relay_connectivity, validate_profile_unlock_with_passphrase,
};
use nostr::{FromBech32, Keys, PublicKey, SecretKey, ToBech32};
use serde::Serialize;

mod commands;

use commands::output::*;
use commands::policy::*;
use commands::prompts::*;
use commands::resolve::*;
use commands::runtime_support::*;

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
    RecoverKey(RecoverKeyArgs),
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
        /// Provide the profile passphrase explicitly (else read from stdin
        /// when stdin is a pipe, or prompt on TTY).
        #[arg(long, conflicts_with = "passphrase_file")]
        passphrase: Option<String>,
        #[arg(long, conflicts_with = "passphrase")]
        passphrase_file: Option<String>,
    },
    Stop {
        #[arg(long)]
        profile: String,
    },
    Restart {
        #[arg(long)]
        profile: String,
        #[arg(long, conflicts_with = "passphrase_file")]
        passphrase: Option<String>,
        #[arg(long, conflicts_with = "passphrase")]
        passphrase_file: Option<String>,
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
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
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
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
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
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
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
    passphrase_env: Option<String>,
    #[arg(long)]
    package_password_env: Option<String>,
}

#[derive(Debug, Args)]
struct RecoverKeyArgs {
    /// Local profile that supplies the group package and this device's own
    /// share (unlocked with the profile passphrase).
    #[arg(long)]
    profile: String,
    /// Other members' `bfshare` packages (path or inline). Supply
    /// `threshold - 1` of them; pair each with a `--bfshare-secret` by order.
    #[arg(long = "bfshare")]
    bfshares: Vec<String>,
    /// Package secret for each `--bfshare`, in the same order.
    #[arg(long = "bfshare-secret")]
    bfshare_secrets: Vec<String>,
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
    /// Write the recovered group `nsec` to this file (created at 0o600).
    #[arg(long)]
    out: String,
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
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
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
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
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
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
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
    #[arg(long, conflicts_with = "passphrase_file")]
    passphrase: Option<String>,
    #[arg(long, conflicts_with = "passphrase")]
    passphrase_file: Option<String>,
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
    passphrase_env: Option<String>,
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
    // C.4: `--token` argv was removed; the daemon child now reads its
    // expected token from `daemon.json` keyed by `--profile`. Keep this
    // comment in place so anyone grep-ing for `--token` finds the rationale.
}

#[tokio::main]
async fn main() -> Result<()> {
    // C.1: tighten the process-wide umask before any file creation. Every
    // subsequent `OpenOptions::create()`, profile manifest write, daemon
    // metadata write, etc. inherits 0o600/0o700 defaults from this single
    // syscall. The explicit chmod helpers in `bifrost_profile::fs_guard`
    // are belt-and-braces — this is the suspenders.
    //
    // SAFETY: `libc::umask` is FFI to a single process-global mutator with
    // no other side effects.
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }

    let cli = Cli::parse();
    configure_trace_env(&cli.trace)?;
    init_tracing(log_options(&cli.trace));
    let paths = ShellPaths::resolve()?;

    match cli.command {
        Commands::Import(args) => commands::imports::handle_import(&paths, args).await?,
        Commands::Export(args) => commands::imports::handle_export(&paths, args)?,
        Commands::RecoverKey(args) => commands::imports::handle_recover_key(&paths, args)?,
        Commands::Onboard(args) => commands::imports::handle_onboard(&paths, args).await?,
        Commands::RotateKey(args) => commands::rotation::handle_rotate_key(&paths, args).await?,
        Commands::RotateKeyset { command } => {
            commands::rotation::handle_rotate_keyset(&paths, command).await?
        }
        Commands::Keygen(args) => commands::rotation::handle_keygen(&paths, args).await?,
        Commands::Setup(args) => commands::imports::handle_setup(&paths, args).await?,
        Commands::Profile { command } => commands::profile::handle_profile(&paths, command).await?,
        Commands::Daemon { command } => commands::runtime::handle_daemon(&paths, command).await?,
        Commands::Runtime { command } => commands::runtime::handle_runtime(&paths, command).await?,
        Commands::Check { command } => commands::runtime::handle_check(&paths, command).await?,
        Commands::Peer { command } => commands::runtime::handle_peer(&paths, command).await?,
        Commands::Policy { command } => commands::runtime::handle_policy(&paths, command).await?,
        Commands::Relays { command } => commands::runtime::handle_relays(&paths, command).await?,
        Commands::Keys { command } => commands::keys::handle_keys(command)?,
        Commands::DaemonRun(args) => handle_daemon_run(&paths, args).await?,
    }

    Ok(())
}

async fn handle_daemon_run(paths: &ShellPaths, args: DaemonRunArgs) -> Result<()> {
    // C.4: read the expected token from `daemon.json` keyed by --profile.
    // The parent wrote the metadata before spawn (0o600, atomic), so by
    // the time we run here the file is in place. We refuse to start if
    // the token is malformed — operator must restart the daemon to
    // regenerate the file.
    let metadata = bifrost_app::native_runtime::read_daemon_metadata(paths, &args.profile)
        .context("read daemon.json for expected token")?;
    let token = bifrost_core::secret::DaemonToken::from_hex(&metadata.token)
        .context("parse expected token from daemon.json")?;

    // C.5: read the passphrase from stdin (newline-terminated). The parent
    // writes the passphrase and then closes the pipe before we get here.
    // If stdin is empty (legacy plaintext profile), `Passphrase` is None.
    let passphrase = match bifrost_app::host::read_passphrase_from_stdin() {
        Ok(p) => Some(p),
        Err(bifrost_app::host::DaemonStartupError::PassphraseStdinClosed) => None,
        Err(err) => return Err(anyhow!("read daemon passphrase: {err}")),
    };

    // C.6: resolve the profile under the supplied passphrase, holding an
    // UnlockSession for the daemon's lifetime so subsequent re-decrypts
    // skip the Argon2id KDF.
    let (_profile, mut resolved, unlock_session) =
        bifrost_app::native_runtime::resolve_profile_runtime_with_unlock_session(
            paths,
            &args.profile,
            passphrase,
        )?;
    resolved.state_path = std::path::PathBuf::from(&resolved.state_path);

    let transport = bifrost_app::host::DaemonTransportConfig {
        socket_path: args.socket_path.into(),
        token,
    };

    // C.7: pass `paths` so the daemon scans the rotation intent journal on
    // startup. Pass the optional unlock session for C.6.
    bifrost_app::host::run_resolved_daemon_with_session(
        resolved,
        transport,
        unlock_session,
        Some(paths),
    )
    .await
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

    use super::{
        Cli,
        commands::resolve::{resolve_profile_label_with, resolve_secret_source_with},
    };

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
        let value = resolve_secret_source_with(
            None,
            None,
            true,
            "encrypted-profile-secret",
            "missing",
            || Ok("prompt-pass\n".to_string()),
        )
        .expect("prompt secret");
        assert_eq!(value, "prompt-pass");
    }

    #[test]
    fn secret_source_rejects_non_tty_without_flags() {
        let err = resolve_secret_source_with(
            None,
            None,
            false,
            "encrypted-profile-secret",
            "missing flags",
            || panic!("prompt should not be used"),
        )
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
            "--passphrase",
            "passphrase",
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
            "--passphrase",
            "passphrase",
            "--start",
        ])
        .expect("start flag should parse");
        match cli.command {
            super::Commands::Import(args) => assert!(args.start),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn recover_key_cli_parses() {
        let cli = Cli::try_parse_from([
            "igloo-shell",
            "recover-key",
            "--profile",
            "device-profile",
            "--bfshare",
            "/tmp/bob.bfshare",
            "--bfshare-secret",
            "bob-secret",
            "--passphrase",
            "passphrase",
            "--out",
            "/tmp/recovered.nsec",
        ])
        .expect("recover-key should parse");
        match cli.command {
            super::Commands::RecoverKey(args) => {
                assert_eq!(args.profile, "device-profile");
                assert_eq!(args.bfshares, vec!["/tmp/bob.bfshare".to_string()]);
                assert_eq!(args.bfshare_secrets, vec!["bob-secret".to_string()]);
                assert_eq!(args.out, "/tmp/recovered.nsec");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn recover_key_cli_rejects_start_flag() {
        // recover-key reconstructs the group nsec; it never creates a device
        // profile or daemon, so the legacy --start flow is gone.
        let err = Cli::try_parse_from([
            "igloo-shell",
            "recover-key",
            "--profile",
            "device-profile",
            "--out",
            "/tmp/recovered.nsec",
            "--start",
        ])
        .expect_err("removed flag should fail");
        assert!(err.to_string().contains("--start"));
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
            "--passphrase",
            "passphrase",
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
            "--passphrase",
            "passphrase",
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
            "--passphrase",
            "passphrase",
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
            "--passphrase",
            "passphrase",
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
            "--passphrase",
            "passphrase",
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
            "--passphrase",
            "passphrase",
            "--distribution-secret",
            "dist",
            "--start",
            "--json",
        ])
        .expect_err("conflicting flags should fail");
        assert!(err.to_string().contains("--start"));
    }
}
