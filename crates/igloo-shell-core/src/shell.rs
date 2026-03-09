use std::fs;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use anyhow::{Context, Result, anyhow, bail};
use bifrost_app::host::{ControlCommand, DaemonClient, DaemonTransportConfig};
use bifrost_app::onboarding::{
    BootstrapImportResult, BootstrapValidationReport, complete_onboarding_package,
    persist_validated_onboarding_state,
};
use bifrost_app::runtime::{AppOptions, PeerConfig, ResolvedAppConfig};
use bifrost_codec::{parse_group_package, parse_share_package, wire::GroupPackageWire, wire::SharePackageWire};
use bifrost_core::types::PeerPolicy;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use frostr_utils::decode_onboarding_package;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use tokio_tungstenite::connect_async;

const SCHEMA_VERSION: u32 = 1;
const VAULT_ENV_PASSPHRASE: &str = "IGLOO_SHELL_VAULT_PASSPHRASE";
const ONBOARDING_ENV_PASSPHRASE: &str = "IGLOO_SHELL_ONBOARDING_PASSWORD";
const VAULT_VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct ShellPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub groups_dir: PathBuf,
    pub vault_dir: PathBuf,
    pub state_profiles_dir: PathBuf,
    pub config_path: PathBuf,
    pub relay_profiles_path: PathBuf,
    pub imports_dir: PathBuf,
}

impl ShellPaths {
    pub fn resolve() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set"))?;

        let config_root = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let data_root = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local").join("share"));
        let state_root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local").join("state"));

        let config_dir = config_root.join("igloo-shell");
        let data_dir = data_root.join("igloo-shell");
        let state_dir = state_root.join("igloo-shell");

        Ok(Self {
            profiles_dir: config_dir.join("profiles"),
            groups_dir: data_dir.join("groups"),
            vault_dir: data_dir.join("vault"),
            state_profiles_dir: state_dir.join("profiles"),
            config_path: config_dir.join("config.json"),
            relay_profiles_path: config_dir.join("relay-profiles.json"),
            imports_dir: data_dir.join("imports"),
            config_dir,
            data_dir,
            state_dir,
        })
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [
            &self.config_dir,
            &self.data_dir,
            &self.state_dir,
            &self.profiles_dir,
            &self.groups_dir,
            &self.vault_dir,
            &self.imports_dir,
            &self.state_profiles_dir,
        ] {
            fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        Ok(())
    }

    pub fn profile_path(&self, profile_id: &str) -> PathBuf {
        self.profiles_dir.join(format!("{profile_id}.json"))
    }

    pub fn profile_state_dir(&self, profile_id: &str) -> PathBuf {
        self.state_profiles_dir.join(profile_id)
    }

    pub fn daemon_metadata_path(&self, profile_id: &str) -> PathBuf {
        self.profile_state_dir(profile_id).join("daemon.json")
    }

    pub fn daemon_log_path(&self, profile_id: &str) -> PathBuf {
        self.profile_state_dir(profile_id).join("daemon.log")
    }

    pub fn vault_metadata_path(&self, vault_id: &str) -> PathBuf {
        self.vault_dir.join(format!("{vault_id}.json"))
    }

    pub fn vault_ciphertext_path(&self, vault_id: &str) -> PathBuf {
        self.vault_dir.join(format!("{vault_id}.enc"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellConfig {
    pub schema_version: u32,
    pub default_relay_profile_id: Option<String>,
    pub last_used_profile_id: Option<String>,
    #[serde(default)]
    pub keyring_preference: KeyringPreference,
    #[serde(default)]
    pub fallback_unlock_mode: FallbackUnlockMode,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            default_relay_profile_id: None,
            last_used_profile_id: None,
            keyring_preference: KeyringPreference::PreferOsKeyring,
            fallback_unlock_mode: FallbackUnlockMode::Passphrase,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyringPreference {
    #[default]
    PreferOsKeyring,
    PassphraseOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FallbackUnlockMode {
    #[default]
    Passphrase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayProfile {
    pub id: String,
    pub label: String,
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileManifest {
    pub id: String,
    pub label: String,
    pub group_ref: String,
    pub share_ref: String,
    pub relay_profile: String,
    #[serde(default)]
    pub runtime_options: Value,
    #[serde(default)]
    pub policy_overrides: Value,
    pub state_path: String,
    pub daemon_socket_path: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub id: String,
    pub kind: String,
    pub source: String,
    pub ciphertext_path: String,
    pub key_source: String,
    pub salt_hex: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonMetadata {
    pub profile_id: String,
    pub pid: u32,
    pub socket_path: String,
    pub token: String,
    pub log_path: String,
    pub started_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileDoctorReport {
    pub profile_id: String,
    pub ok: bool,
    pub missing_paths: Vec<String>,
    pub relay_profile_exists: bool,
    pub group_present: bool,
    pub share_managed: bool,
    pub vault_record_exists: bool,
    pub vault_unlock_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyOverridesDocument {
    #[serde(default)]
    default_policy: Option<PeerPolicy>,
    #[serde(default)]
    peer_overrides: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProfileImportResult {
    ProfileCreated {
        profile: ProfileManifest,
        vault_record: VaultRecord,
        diagnostics: Option<BootstrapValidationReport>,
        warnings: Vec<String>,
    },
    OnboardingStaged {
        vault_record: VaultRecord,
        staged_onboarding: StagedOnboardingImport,
        warnings: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileExportResult {
    pub profile_id: String,
    pub out_dir: String,
    pub group_path: Option<String>,
    pub share_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedOnboardingImport {
    pub id: String,
    pub vault_record_id: String,
    pub label: Option<String>,
    pub relay_profile: String,
    pub peer_pubkey: String,
    pub relays: Vec<String>,
    pub challenge_hex32: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupResult {
    pub import: ProfileImportResult,
    pub daemon_started: bool,
    pub daemon: Option<DaemonMetadata>,
}

#[derive(Debug, Clone)]
pub struct SetupRequest {
    pub group_path: Option<PathBuf>,
    pub share_path: Option<PathBuf>,
    pub onboarding_package_path: Option<PathBuf>,
    pub label: Option<String>,
    pub relay_profile: Option<String>,
    pub vault_passphrase: Option<String>,
    pub onboarding_password: Option<String>,
}

pub fn load_shell_config(paths: &ShellPaths) -> Result<ShellConfig> {
    if !paths.config_path.exists() {
        return Ok(ShellConfig::default());
    }
    read_json(&paths.config_path)
}

pub fn save_shell_config(paths: &ShellPaths, config: &ShellConfig) -> Result<()> {
    write_json(&paths.config_path, config)
}

pub fn load_relay_profiles(paths: &ShellPaths) -> Result<Vec<RelayProfile>> {
    if !paths.relay_profiles_path.exists() {
        return Ok(Vec::new());
    }
    let mut profiles: Vec<RelayProfile> = read_json(&paths.relay_profiles_path)?;
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(profiles)
}

pub fn save_relay_profiles(paths: &ShellPaths, profiles: &[RelayProfile]) -> Result<()> {
    write_json(&paths.relay_profiles_path, profiles)
}

pub fn read_vault_record(paths: &ShellPaths, vault_id: &str) -> Result<VaultRecord> {
    let path = paths.vault_metadata_path(vault_id);
    if !path.exists() {
        bail!("unknown vault record {vault_id}");
    }
    read_json(&path)
}

pub fn write_vault_record(paths: &ShellPaths, record: &VaultRecord) -> Result<()> {
    write_json(&paths.vault_metadata_path(&record.id), record)
}

pub fn list_profiles(paths: &ShellPaths) -> Result<Vec<ProfileManifest>> {
    if !paths.profiles_dir.exists() {
        return Ok(Vec::new());
    }

    let mut profiles: Vec<ProfileManifest> = Vec::new();
    for entry in fs::read_dir(&paths.profiles_dir)
        .with_context(|| format!("read {}", paths.profiles_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        profiles.push(read_json(&path)?);
    }

    profiles.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
    Ok(profiles)
}

pub fn read_profile(paths: &ShellPaths, profile_id: &str) -> Result<ProfileManifest> {
    let path = paths.profile_path(profile_id);
    if !path.exists() {
        bail!("unknown profile {profile_id}");
    }
    read_json(&path)
}

pub fn read_relay_profile(paths: &ShellPaths, relay_profile_id: &str) -> Result<RelayProfile> {
    load_relay_profiles(paths)?
        .into_iter()
        .find(|profile| profile.id == relay_profile_id)
        .ok_or_else(|| anyhow!("unknown relay profile {relay_profile_id}"))
}

pub fn write_profile(paths: &ShellPaths, profile: &ProfileManifest) -> Result<()> {
    write_json(&paths.profile_path(&profile.id), profile)
}

pub fn remove_profile(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    let profile = read_profile(paths, profile_id)?;
    let path = paths.profile_path(profile_id);
    fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;

    let state_dir = paths.profile_state_dir(profile_id);
    if state_dir.exists() {
        fs::remove_dir_all(&state_dir).with_context(|| format!("remove {}", state_dir.display()))?;
    }

    if is_managed_group_path(paths, &profile.group_ref)
        && !is_group_ref_in_use(paths, &profile.id, &profile.group_ref)?
        && Path::new(&profile.group_ref).exists()
    {
        fs::remove_file(&profile.group_ref).with_context(|| format!("remove {}", profile.group_ref))?;
    }

    if let Ok(record) = read_vault_record(paths, &profile.share_ref)
        && !is_vault_ref_in_use(paths, &profile.id, &record.id)?
    {
        remove_vault_record(paths, &record.id)?;
    }

    let mut config = load_shell_config(paths)?;
    if config.last_used_profile_id.as_deref() == Some(profile_id) {
        config.last_used_profile_id = None;
        save_shell_config(paths, &config)?;
    }
    Ok(())
}

pub fn read_daemon_metadata(paths: &ShellPaths, profile_id: &str) -> Result<DaemonMetadata> {
    let path = paths.daemon_metadata_path(profile_id);
    if !path.exists() {
        bail!("daemon metadata is not present for profile {profile_id}");
    }
    read_json(&path)
}

pub fn write_daemon_metadata(
    paths: &ShellPaths,
    profile_id: &str,
    metadata: &DaemonMetadata,
) -> Result<()> {
    write_json(&paths.daemon_metadata_path(profile_id), metadata)
}

pub fn remove_daemon_metadata(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    let path = paths.daemon_metadata_path(profile_id);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

pub fn doctor_profile(paths: &ShellPaths, profile: &ProfileManifest) -> Result<ProfileDoctorReport> {
    let relays = load_relay_profiles(paths)?;
    let relay_profile_exists = relays.iter().any(|entry| entry.id == profile.relay_profile);

    let mut missing_paths = Vec::new();
    let group_present = Path::new(&profile.group_ref).exists();
    if !group_present {
        missing_paths.push(profile.group_ref.clone());
    }

    let (share_managed, vault_record_exists, vault_unlock_ok) =
        if let Ok(record) = read_vault_record(paths, &profile.share_ref) {
            let ciphertext_exists = Path::new(&record.ciphertext_path).exists();
            if !ciphertext_exists {
                missing_paths.push(record.ciphertext_path.clone());
            }
            let unlock_ok = ciphertext_exists && decrypt_vault_record(paths, &record, None).is_ok();
            (true, ciphertext_exists, unlock_ok)
        } else {
            let plaintext_exists = Path::new(&profile.share_ref).exists();
            if !plaintext_exists {
                missing_paths.push(profile.share_ref.clone());
            }
            (false, plaintext_exists, plaintext_exists)
        };

    let state_parent = Path::new(&profile.state_path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.profile_state_dir(&profile.id));
    if !state_parent.exists() {
        missing_paths.push(state_parent.display().to_string());
    }

    Ok(ProfileDoctorReport {
        profile_id: profile.id.clone(),
        ok: relay_profile_exists
            && group_present
            && vault_record_exists
            && vault_unlock_ok
            && missing_paths.is_empty(),
        missing_paths,
        relay_profile_exists,
        group_present,
        share_managed,
        vault_record_exists,
        vault_unlock_ok,
    })
}

pub fn set_profile_default_policy(
    paths: &ShellPaths,
    profile_id: &str,
    policy: PeerPolicy,
) -> Result<ProfileManifest> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    document.default_policy = Some(policy);
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok(profile)
}

pub fn set_profile_peer_policy(
    paths: &ShellPaths,
    profile_id: &str,
    peer_pubkey: &str,
    policy: PeerPolicy,
) -> Result<ProfileManifest> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    if let Some(existing) = document
        .peer_overrides
        .iter_mut()
        .find(|entry| entry.pubkey == peer_pubkey)
    {
        existing.policy = policy;
    } else {
        document.peer_overrides.push(PeerConfig {
            pubkey: peer_pubkey.to_string(),
            policy,
        });
    }
    document
        .peer_overrides
        .sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok(profile)
}

pub fn clear_profile_peer_policy(
    paths: &ShellPaths,
    profile_id: &str,
    peer_pubkey: &str,
) -> Result<(ProfileManifest, PeerPolicy)> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    document
        .peer_overrides
        .retain(|entry| entry.pubkey != peer_pubkey);
    let effective_policy = document.default_policy.clone().unwrap_or_default();
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok((profile, effective_policy))
}

pub fn resolve_profile_runtime(
    paths: &ShellPaths,
    profile_id: &str,
) -> Result<(ProfileManifest, ResolvedAppConfig)> {
    let profile = read_profile(paths, profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;

    let group_raw = fs::read_to_string(&profile.group_ref)
        .with_context(|| format!("read {}", profile.group_ref))?;
    let share_raw = load_share_payload(paths, &profile)?;
    let group = parse_group_package(&group_raw).context("parse profile group package")?;
    let share = parse_share_package(&share_raw).context("parse profile share package")?;
    let peers = resolve_policy_peers(&group, &share, profile.policy_overrides.clone())
        .context("resolve peer policy overrides")?;
    let options: AppOptions = if profile.runtime_options.is_null() {
        AppOptions::default()
    } else {
        serde_json::from_value(profile.runtime_options.clone())
            .context("parse runtime options")?
    };

    Ok((
        profile.clone(),
        ResolvedAppConfig {
            group,
            share,
            state_path: PathBuf::from(&profile.state_path),
            relays: relay_profile.relays,
            peers,
            options,
        },
    ))
}

#[cfg(unix)]
pub fn daemon_client(paths: &ShellPaths, profile_id: &str) -> Result<DaemonClient> {
    let metadata = read_daemon_metadata(paths, profile_id)?;
    Ok(DaemonClient::new(
        PathBuf::from(metadata.socket_path),
        metadata.token,
    ))
}

pub fn daemon_log_path(paths: &ShellPaths, profile_id: &str) -> PathBuf {
    paths.daemon_log_path(profile_id)
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayProbeResult {
    pub relay: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayConnectivityReport {
    pub relay_profile_id: String,
    pub relays: Vec<RelayProbeResult>,
}

pub fn build_daemon_transport(profile: &ProfileManifest) -> DaemonTransportConfig {
    let socket_path = shorten_unix_socket_path(&profile.daemon_socket_path, &profile.id);
    DaemonTransportConfig {
        socket_path,
        token: format!("daemon-{}-{}", profile.id, now_unix_secs()),
    }
}

pub async fn test_relay_connectivity(
    paths: &ShellPaths,
    relay_profile_id: Option<String>,
) -> Result<RelayConnectivityReport> {
    let selected = match relay_profile_id {
        Some(profile_id) => profile_id,
        None => {
            let config = load_shell_config(paths)?;
            config
                .default_relay_profile_id
                .ok_or_else(|| anyhow!("no default relay profile is configured"))?
        }
    };
    let profile = read_relay_profile(paths, &selected)?;
    let mut relays = Vec::with_capacity(profile.relays.len());
    for relay in &profile.relays {
        let outcome = match connect_async(relay.as_str()).await {
            Ok((stream, _)) => {
                let mut stream = stream;
                let _ = stream.close(None).await;
                RelayProbeResult {
                    relay: relay.clone(),
                    ok: true,
                    error: None,
                }
            }
            Err(err) => RelayProbeResult {
                relay: relay.clone(),
                ok: false,
                error: Some(err.to_string()),
            },
        };
        relays.push(outcome);
    }

    Ok(RelayConnectivityReport {
        relay_profile_id: profile.id,
        relays,
    })
}

#[cfg(unix)]
pub async fn start_profile_daemon(paths: &ShellPaths, profile_id: &str) -> Result<DaemonMetadata> {
    paths.ensure()?;
    let profile = read_profile(paths, profile_id)?;
    let transport = build_daemon_transport(&profile);
    let log_path = paths.daemon_log_path(profile_id);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let stderr = stdout.try_clone().context("clone daemon log handle")?;
    let exe = std::env::current_exe().context("resolve current executable")?;
    let child = Command::new(exe)
        .arg("__daemon-run")
        .arg("--profile")
        .arg(profile_id)
        .arg("--socket-path")
        .arg(&transport.socket_path)
        .arg("--token")
        .arg(&transport.token)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("spawn igloo-shell daemon")?;

    let metadata = DaemonMetadata {
        profile_id: profile_id.to_string(),
        pid: child.id(),
        socket_path: transport.socket_path.display().to_string(),
        token: transport.token.clone(),
        log_path: log_path.display().to_string(),
        started_at: now_unix_secs(),
    };
    write_daemon_metadata(paths, profile_id, &metadata)?;

    let client = DaemonClient::new(PathBuf::from(&metadata.socket_path), metadata.token.clone());
    let mut last_error = None;
    for _ in 0..50 {
        match client.request(ControlCommand::RuntimeMetadata).await {
            Ok(response) if response.ok => return Ok(metadata),
            Ok(response) => last_error = response.error,
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    Err(anyhow!(
        "daemon did not become ready for profile {profile_id}: {}",
        last_error.unwrap_or_else(|| "unknown startup failure".to_string())
    ))
}

#[cfg(unix)]
pub async fn stop_profile_daemon(paths: &ShellPaths, profile_id: &str) -> Result<Value> {
    let client = daemon_client(paths, profile_id)?;
    let result = client.request_ok(ControlCommand::Shutdown).await?;
    remove_daemon_metadata(paths, profile_id)?;
    Ok(result)
}

#[cfg(unix)]
pub async fn daemon_runtime_query(
    paths: &ShellPaths,
    profile_id: &str,
    command: ControlCommand,
) -> Result<Value> {
    daemon_client(paths, profile_id)?.request_ok(command).await
}

pub fn import_profile_from_files(
    paths: &ShellPaths,
    group_path: &Path,
    share_path: &Path,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let group_raw =
        fs::read_to_string(group_path).with_context(|| format!("read {}", group_path.display()))?;
    let share_raw =
        fs::read_to_string(share_path).with_context(|| format!("read {}", share_path.display()))?;
    let group = parse_group_package(&group_raw).context("parse group package")?;
    let share = parse_share_package(&share_raw).context("parse share package")?;

    let relay_profile_id = resolve_relay_profile_id(paths, relay_profile)?;
    let now = now_unix_secs();
    let group_ref = store_group_package(paths, &group)?;
    let vault_record = store_secret_payload(
        paths,
        "share_package",
        "file_import",
        &share_raw,
        vault_passphrase,
    )?;
    let profile_id = generate_profile_id(label.as_deref());
    let profile = build_profile_manifest(
        paths,
        &profile_id,
        label.unwrap_or_else(|| format!("device-{}", share.idx)),
        group_ref,
        vault_record.id.clone(),
        relay_profile_id,
        now,
    );
    fs::create_dir_all(paths.profile_state_dir(&profile.id))
        .with_context(|| format!("create {}", paths.profile_state_dir(&profile.id).display()))?;

    write_profile(paths, &profile)?;
    touch_last_used_profile(paths, &profile.id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile,
        vault_record,
        diagnostics: None,
        warnings: Vec::new(),
    })
}

pub fn stage_onboarding_import(
    paths: &ShellPaths,
    package_path: &Path,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
    onboarding_password: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let package_raw = fs::read_to_string(package_path)
        .with_context(|| format!("read {}", package_path.display()))?;
    let password = resolve_secret(
        onboarding_password,
        ONBOARDING_ENV_PASSPHRASE,
        "onboarding package password",
    )?;
    let decoded = decode_onboarding_package(&package_raw, Some(password.as_str()))
        .context("decode onboarding package")?;
    let relay_profile_id = relay_profile
        .unwrap_or_else(|| format!("onboarding-{}", now_unix_secs()));
    if read_relay_profile(paths, &relay_profile_id).is_err() {
        replace_relay_profile(
            paths,
            RelayProfile {
                id: relay_profile_id.clone(),
                label: label
                    .clone()
                    .unwrap_or_else(|| "Imported Onboarding Package".to_string()),
                relays: decoded.relays.clone(),
            },
        )?;
    }

    let vault_record = store_secret_payload(
        paths,
        "onboarding_package",
        "file_import",
        &package_raw,
        vault_passphrase,
    )?;
    let staged = StagedOnboardingImport {
        id: format!("onboarding-{}", now_unix_secs()),
        vault_record_id: vault_record.id.clone(),
        label,
        relay_profile: relay_profile_id,
        peer_pubkey: hex::encode(decoded.peer_pk),
        relays: decoded.relays,
        challenge_hex32: decoded.challenge.map(hex::encode),
        created_at: now_unix_secs(),
    };
    write_json(
        &paths.imports_dir.join(format!("{}.json", staged.id)),
        &staged,
    )?;

    Ok(ProfileImportResult::OnboardingStaged {
        vault_record,
        staged_onboarding: staged,
        warnings: vec![
            "onboarding package staged in vault; final profile creation requires the ephemeral onboarding runtime".to_string(),
        ],
    })
}

pub async fn import_profile_from_onboarding_package(
    paths: &ShellPaths,
    package_path: &Path,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
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
        vault_passphrase,
        onboarding_password,
    )
    .await
}

pub async fn import_profile_from_onboarding_value(
    paths: &ShellPaths,
    package_raw: &str,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
    onboarding_password: Option<String>,
) -> Result<ProfileImportResult> {
    import_profile_from_onboarding_value_with(
        paths,
        package_raw,
        label,
        relay_profile,
        vault_passphrase,
        onboarding_password,
        |decoded| async move { complete_onboarding_package(decoded, Duration::from_secs(30)).await },
    )
    .await
}

async fn import_profile_from_onboarding_value_with<F, Fut>(
    paths: &ShellPaths,
    package_raw: &str,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
    onboarding_password: Option<String>,
    complete: F,
) -> Result<ProfileImportResult>
where
    F: FnOnce(frostr_utils::OnboardingPackage) -> Fut,
    Fut: std::future::Future<Output = Result<BootstrapImportResult>>,
{
    paths.ensure()?;
    let vault_passphrase_for_share = vault_passphrase.clone();
    let password = resolve_secret(
        onboarding_password,
        ONBOARDING_ENV_PASSPHRASE,
        "onboarding package password",
    )?;
    let decoded = decode_onboarding_package(&package_raw, Some(password.as_str()))
        .context("decode onboarding package")?;
    let relay_profile_id = ensure_onboarding_relay_profile(paths, relay_profile, label.as_deref(), &decoded.relays)?;
    let vault_record = store_secret_payload(
        paths,
        "onboarding_package",
        "file_import",
        &package_raw,
        vault_passphrase,
    )?;

    let completion = match complete(decoded).await {
        Ok(completion) => completion,
        Err(err) => {
            let _ = remove_vault_record(paths, &vault_record.id);
            return Err(err);
        }
    };

    let share_raw = serde_json::to_string_pretty(&SharePackageWire::from(completion.share.clone()))
        .context("serialize onboarded share package")?;
    let share_record = store_secret_payload(
        paths,
        "share_package",
        "invite_accept",
        &share_raw,
        vault_passphrase_for_share,
    )?;
    let _ = remove_vault_record(paths, &vault_record.id);

    finalize_onboarding_import(paths, completion, label, relay_profile_id, share_record)
}

pub fn export_profile(
    paths: &ShellPaths,
    profile_id: &str,
    out_dir: &Path,
    vault_passphrase: Option<String>,
) -> Result<ProfileExportResult> {
    let profile = read_profile(paths, profile_id)?;
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let group_path = if Path::new(&profile.group_ref).exists() {
        let dest = out_dir.join("group.json");
        fs::copy(&profile.group_ref, &dest)
            .with_context(|| format!("copy {} to {}", profile.group_ref, dest.display()))?;
        Some(dest.display().to_string())
    } else {
        None
    };

    let share_raw = load_share_payload_with_passphrase(paths, &profile, vault_passphrase)?;
    let share_path = out_dir.join(format!("share-{}.json", profile.id));
    fs::write(&share_path, share_raw).with_context(|| format!("write {}", share_path.display()))?;

    Ok(ProfileExportResult {
        profile_id: profile.id,
        out_dir: out_dir.display().to_string(),
        group_path,
        share_path: share_path.display().to_string(),
    })
}

pub async fn run_setup(paths: &ShellPaths, request: SetupRequest, start_daemon: bool) -> Result<SetupResult> {
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
            request.vault_passphrase,
        )?,
        (None, None, Some(package)) => {
            import_profile_from_onboarding_package(
                paths,
                package,
                request.label,
                request.relay_profile,
                request.vault_passphrase,
                request.onboarding_password,
            )
            .await?
        }
        _ => bail!("setup requires either --group and --share, or --onboarding-package"),
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

pub fn replace_relay_profile(paths: &ShellPaths, next: RelayProfile) -> Result<()> {
    validate_relay_profile(&next)?;
    let mut profiles = load_relay_profiles(paths)?;
    profiles.retain(|entry| entry.id != next.id);
    profiles.push(next);
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    save_relay_profiles(paths, &profiles)
}

pub fn add_relays(paths: &ShellPaths, profile_id: &str, relays: &[String]) -> Result<()> {
    let mut profiles = load_relay_profiles(paths)?;
    let Some(profile) = profiles.iter_mut().find(|entry| entry.id == profile_id) else {
        bail!("unknown relay profile {profile_id}");
    };
    for relay in relays {
        if !profile.relays.iter().any(|existing| existing == relay) {
            profile.relays.push(relay.clone());
        }
    }
    validate_relay_profile(profile)?;
    save_relay_profiles(paths, &profiles)
}

pub fn remove_relays(paths: &ShellPaths, profile_id: &str, relays: &[String]) -> Result<()> {
    let mut profiles = load_relay_profiles(paths)?;
    let Some(profile) = profiles.iter_mut().find(|entry| entry.id == profile_id) else {
        bail!("unknown relay profile {profile_id}");
    };
    profile.relays.retain(|relay| !relays.iter().any(|value| value == relay));
    validate_relay_profile(profile)?;
    save_relay_profiles(paths, &profiles)
}

pub fn set_default_relay_profile(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    let profiles = load_relay_profiles(paths)?;
    if !profiles.iter().any(|entry| entry.id == profile_id) {
        bail!("unknown relay profile {profile_id}");
    }
    let mut config = load_shell_config(paths)?;
    config.default_relay_profile_id = Some(profile_id.to_string());
    save_shell_config(paths, &config)
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn resolve_relay_profile_id(paths: &ShellPaths, requested: Option<String>) -> Result<String> {
    if let Some(profile_id) = requested {
        read_relay_profile(paths, &profile_id)?;
        return Ok(profile_id);
    }

    let config = load_shell_config(paths)?;
    if let Some(profile_id) = config.default_relay_profile_id {
        read_relay_profile(paths, &profile_id)?;
        return Ok(profile_id);
    }

    let profiles = load_relay_profiles(paths)?;
    let Some(first) = profiles.first() else {
        bail!("no relay profile configured; use `igloo-shell relays set ...` first");
    };
    Ok(first.id.clone())
}

fn ensure_onboarding_relay_profile(
    paths: &ShellPaths,
    requested: Option<String>,
    label: Option<&str>,
    relays: &[String],
) -> Result<String> {
    if let Some(profile_id) = requested {
        if read_relay_profile(paths, &profile_id).is_ok() {
            return Ok(profile_id);
        }
        replace_relay_profile(
            paths,
            RelayProfile {
                id: profile_id.clone(),
                label: label.unwrap_or(&profile_id).to_string(),
                relays: relays.to_vec(),
            },
        )?;
        return Ok(profile_id);
    }

    if let Some(existing) = load_relay_profiles(paths)?
        .into_iter()
        .find(|profile| profile.relays == relays)
    {
        return Ok(existing.id);
    }

    let profile_id = format!("onboarding-{}", now_unix_secs());
    replace_relay_profile(
        paths,
        RelayProfile {
            id: profile_id.clone(),
            label: label.unwrap_or("Imported Onboarding Package").to_string(),
            relays: relays.to_vec(),
        },
    )?;
    Ok(profile_id)
}

fn store_group_package(paths: &ShellPaths, group: &bifrost_core::types::GroupPackage) -> Result<String> {
    let path = paths
        .groups_dir
        .join(format!("{}.json", hex::encode(group.group_pk)));
    if !path.exists() {
        write_json(&path, &GroupPackageWire::from(group.clone()))?;
    }
    Ok(path.display().to_string())
}

fn build_profile_manifest(
    paths: &ShellPaths,
    profile_id: &str,
    label: String,
    group_ref: String,
    share_ref: String,
    relay_profile: String,
    created_at: u64,
) -> ProfileManifest {
    let state_dir = paths.profile_state_dir(profile_id);
    ProfileManifest {
        id: profile_id.to_string(),
        label,
        group_ref,
        share_ref,
        relay_profile,
        runtime_options: Value::Null,
        policy_overrides: serde_json::json!({
            "default_policy": PeerPolicy::default(),
            "peer_overrides": []
        }),
        state_path: state_dir.join("signer-state.bin").display().to_string(),
        daemon_socket_path: state_dir.join("daemon.sock").display().to_string(),
        created_at,
        last_used_at: Some(created_at),
    }
}

fn parse_policy_overrides_doc(value: Value) -> Result<PolicyOverridesDocument> {
    if value.is_null() {
        return Ok(PolicyOverridesDocument {
            default_policy: None,
            peer_overrides: Vec::new(),
        });
    }

    if let Ok(peer_overrides) = serde_json::from_value::<Vec<PeerConfig>>(value.clone()) {
        return Ok(PolicyOverridesDocument {
            default_policy: None,
            peer_overrides,
        });
    }

    serde_json::from_value(value).context("parse policy overrides document")
}

fn resolve_policy_peers(
    group: &bifrost_core::types::GroupPackage,
    share: &bifrost_core::types::SharePackage,
    value: Value,
) -> Result<Vec<PeerConfig>> {
    let document = parse_policy_overrides_doc(value)?;
    let local_pubkey = derive_member_pubkey_hex(share.seckey)?;
    let mut peers = document.peer_overrides;

    if let Some(default_policy) = document.default_policy {
        for member in &group.members {
            let pubkey = hex::encode(&member.pubkey[1..]);
            if pubkey == local_pubkey || peers.iter().any(|peer| peer.pubkey == pubkey) {
                continue;
            }
            peers.push(PeerConfig {
                pubkey,
                policy: default_policy.clone(),
            });
        }
    }

    peers.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    peers.dedup_by(|a, b| a.pubkey == b.pubkey);
    Ok(peers)
}

fn derive_member_pubkey_hex(seckey: [u8; 32]) -> Result<String> {
    let secret = k256::SecretKey::from_slice(&seckey).context("invalid share seckey")?;
    let point = secret.public_key().to_encoded_point(true);
    Ok(hex::encode(&point.as_bytes()[1..]))
}

fn generate_profile_id(label: Option<&str>) -> String {
    let base = label
        .map(slugify)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "profile".to_string());
    format!("{base}-{}", now_unix_secs())
}

fn slugify(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn store_secret_payload(
    paths: &ShellPaths,
    kind: &str,
    source: &str,
    payload: &str,
    passphrase: Option<String>,
) -> Result<VaultRecord> {
    let passphrase = resolve_secret(passphrase, VAULT_ENV_PASSPHRASE, "vault passphrase")?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_vault_key(&passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload.as_bytes())
        .map_err(|_| anyhow!("vault encryption failure"))?;
    let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    envelope.push(VAULT_VERSION);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);

    let now = now_unix_secs();
    let id = format!("vault-{now}-{}", random_hex(4));
    let ciphertext_path = paths.vault_ciphertext_path(&id);
    fs::write(&ciphertext_path, envelope)
        .with_context(|| format!("write {}", ciphertext_path.display()))?;

    let record = VaultRecord {
        id: id.clone(),
        kind: kind.to_string(),
        source: source.to_string(),
        ciphertext_path: ciphertext_path.display().to_string(),
        key_source: "passphrase".to_string(),
        salt_hex: hex::encode(salt),
        created_at: now,
        updated_at: now,
    };
    write_vault_record(paths, &record)?;
    Ok(record)
}

fn decrypt_vault_record(
    _paths: &ShellPaths,
    record: &VaultRecord,
    passphrase: Option<String>,
) -> Result<String> {
    let passphrase = resolve_secret(passphrase, VAULT_ENV_PASSPHRASE, "vault passphrase")?;
    let salt = hex::decode(&record.salt_hex).context("decode vault salt")?;
    let envelope = fs::read(&record.ciphertext_path)
        .with_context(|| format!("read {}", record.ciphertext_path))?;
    if envelope.len() < 1 + 12 + 16 {
        bail!("vault ciphertext is too short");
    }
    if envelope[0] != VAULT_VERSION {
        bail!("unsupported vault version {}", envelope[0]);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&envelope[1..13]);
    let key = derive_vault_key(&passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), &envelope[13..])
        .map_err(|_| anyhow!("vault decryption failure"))?;
    String::from_utf8(plaintext).context("vault plaintext is not utf8")
}

fn derive_vault_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("derive vault key: {e}"))?;
    Ok(key)
}

fn resolve_secret(value: Option<String>, env_name: &str, label: &str) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    std::env::var(env_name).with_context(|| format!("{label} not provided; set {env_name}"))
}

fn load_share_payload(paths: &ShellPaths, profile: &ProfileManifest) -> Result<String> {
    load_share_payload_with_passphrase(paths, profile, None)
}

fn load_share_payload_with_passphrase(
    paths: &ShellPaths,
    profile: &ProfileManifest,
    passphrase: Option<String>,
) -> Result<String> {
    if let Ok(record) = read_vault_record(paths, &profile.share_ref) {
        return decrypt_vault_record(paths, &record, passphrase);
    }
    fs::read_to_string(&profile.share_ref).with_context(|| format!("read {}", profile.share_ref))
}

fn is_group_ref_in_use(
    paths: &ShellPaths,
    exclude_profile_id: &str,
    group_ref: &str,
) -> Result<bool> {
    Ok(list_profiles(paths)?
        .into_iter()
        .any(|profile| profile.id != exclude_profile_id && profile.group_ref == group_ref))
}

fn is_vault_ref_in_use(paths: &ShellPaths, exclude_profile_id: &str, vault_id: &str) -> Result<bool> {
    Ok(list_profiles(paths)?
        .into_iter()
        .any(|profile| profile.id != exclude_profile_id && profile.share_ref == vault_id))
}

fn remove_vault_record(paths: &ShellPaths, vault_id: &str) -> Result<()> {
    let record = read_vault_record(paths, vault_id)?;
    let metadata_path = paths.vault_metadata_path(vault_id);
    if metadata_path.exists() {
        fs::remove_file(&metadata_path).with_context(|| format!("remove {}", metadata_path.display()))?;
    }
    if Path::new(&record.ciphertext_path).exists() {
        fs::remove_file(&record.ciphertext_path)
            .with_context(|| format!("remove {}", record.ciphertext_path))?;
    }
    Ok(())
}

fn is_managed_group_path(paths: &ShellPaths, value: &str) -> bool {
    Path::new(value).starts_with(&paths.groups_dir)
}

fn touch_last_used_profile(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    let mut config = load_shell_config(paths)?;
    config.last_used_profile_id = Some(profile_id.to_string());
    save_shell_config(paths, &config)
}

fn random_hex(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn shorten_unix_socket_path(raw_path: &str, profile_id: &str) -> PathBuf {
    let path = PathBuf::from(raw_path);
    #[cfg(unix)]
    {
        let raw_len = path.as_os_str().to_string_lossy().len();
        if raw_len >= 96 {
            let digest = sha2::Sha256::digest(profile_id.as_bytes());
            let short = hex::encode(&digest[..6]);
            return std::env::temp_dir().join(format!("igloo-shell-{short}.sock"));
        }
    }
    path
}

fn finalize_onboarding_import(
    paths: &ShellPaths,
    completion: BootstrapImportResult,
    label: Option<String>,
    relay_profile_id: String,
    vault_record: VaultRecord,
) -> Result<ProfileImportResult> {
    let now = now_unix_secs();
    let group_ref = store_group_package(paths, &completion.group)?;
    let profile_id = generate_profile_id(label.as_deref());
    let profile = build_profile_manifest(
        paths,
        &profile_id,
        label.unwrap_or_else(|| format!("onboarded-{}", completion.share.idx)),
        group_ref,
        vault_record.id.clone(),
        relay_profile_id,
        now,
    );
    fs::create_dir_all(paths.profile_state_dir(&profile.id))
        .with_context(|| format!("create {}", paths.profile_state_dir(&profile.id).display()))?;
    let diagnostics = match persist_validated_onboarding_state(Path::new(&profile.state_path), &completion) {
        Ok(report) => report,
        Err(error) => {
            let _ = fs::remove_file(&profile.group_ref);
            let _ = remove_vault_record(paths, &vault_record.id);
            let _ = fs::remove_dir_all(paths.profile_state_dir(&profile.id));
            return Err(error);
        }
    };
    write_profile(paths, &profile)?;
    touch_last_used_profile(paths, &profile.id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile,
        vault_record,
        diagnostics: Some(diagnostics),
        warnings: Vec::new(),
    })
}

fn validate_relay_profile(profile: &RelayProfile) -> Result<()> {
    if profile.id.trim().is_empty() {
        bail!("relay profile id must be non-empty");
    }
    if profile.label.trim().is_empty() {
        bail!("relay profile label must be non-empty");
    }
    if profile.relays.is_empty() {
        bail!("relay profile {} must contain at least one relay", profile.id);
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(value).context("serialize json")?;
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use bifrost_app::host::{ControlCommand, run_resolved_daemon};
    use bifrost_signer::{DeviceState, DeviceStore};
    use bifrost_core::types::{GroupPackage, MemberPackage, SharePackage};
    use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
    use frostr_utils::{CreateKeysetConfig, OnboardingPackage, create_keyset, encode_onboarding_package};
    #[cfg(unix)]
    use crate::relay::NostrRelay;
    #[cfg(unix)]
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn test_paths(name: &str) -> ShellPaths {
        let root = std::env::temp_dir().join(format!(
            "igloo-shell-tests-{}-{}",
            name,
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        ShellPaths {
            config_dir: root.join("config").join("igloo-shell"),
            data_dir: root.join("data").join("igloo-shell"),
            state_dir: root.join("state").join("igloo-shell"),
            profiles_dir: root.join("config").join("igloo-shell").join("profiles"),
            groups_dir: root.join("data").join("igloo-shell").join("groups"),
            vault_dir: root.join("data").join("igloo-shell").join("vault"),
            state_profiles_dir: root.join("state").join("igloo-shell").join("profiles"),
            config_path: root.join("config").join("igloo-shell").join("config.json"),
            relay_profiles_path: root
                .join("config")
                .join("igloo-shell")
                .join("relay-profiles.json"),
            imports_dir: root.join("data").join("igloo-shell").join("imports"),
        }
    }

    fn sample_group() -> GroupPackage {
        GroupPackage {
            group_pk: [9u8; 32],
            threshold: 2,
            members: vec![
                MemberPackage {
                    idx: 1,
                    pubkey: {
                        let mut v = [0u8; 33];
                        v[0] = 0x02;
                        v[1..].copy_from_slice(&[1u8; 32]);
                        v
                    },
                },
                MemberPackage {
                    idx: 2,
                    pubkey: {
                        let mut v = [0u8; 33];
                        v[0] = 0x02;
                        v[1..].copy_from_slice(&[2u8; 32]);
                        v
                    },
                },
            ],
        }
    }

    fn sample_share() -> SharePackage {
        SharePackage {
            idx: 1,
            seckey: [3u8; 32],
        }
    }

    #[test]
    fn set_and_clear_profile_peer_policy_persist_in_manifest() {
        let paths = test_paths("policy-overrides");
        paths.ensure().expect("ensure shell paths");
        replace_relay_profile(
            &paths,
            RelayProfile {
                id: "local".to_string(),
                label: "Local".to_string(),
                relays: vec!["ws://127.0.0.1:8194".to_string()],
            },
        )
        .expect("write relay profile");

        let group_ref = store_group_package(&paths, &sample_group()).expect("store group");
        let share_raw = serde_json::to_string_pretty(&SharePackageWire::from(sample_share()))
            .expect("serialize share");
        let vault_record = store_secret_payload(
            &paths,
            "share_package",
            "test",
            &share_raw,
            Some("vault-pass".to_string()),
        )
        .expect("store share");
        let profile = build_profile_manifest(
            &paths,
            "alice",
            "Alice".to_string(),
            group_ref,
            vault_record.id.clone(),
            "local".to_string(),
            now_unix_secs(),
        );
        fs::create_dir_all(paths.profile_state_dir(&profile.id)).expect("create state dir");
        write_profile(&paths, &profile).expect("write profile");

        let policy = PeerPolicy::from_send_receive(false, true);
        let updated = set_profile_peer_policy(&paths, "alice", "deadbeef", policy.clone())
            .expect("persist peer policy");
        let document = parse_policy_overrides_doc(updated.policy_overrides).expect("parse policy overrides");
        assert_eq!(document.peer_overrides.len(), 1);
        assert_eq!(document.peer_overrides[0].pubkey, "deadbeef");
        assert_eq!(document.peer_overrides[0].policy, policy);

        let (cleared, effective_policy) =
            clear_profile_peer_policy(&paths, "alice", "deadbeef").expect("clear peer policy");
        let cleared_doc =
            parse_policy_overrides_doc(cleared.policy_overrides).expect("parse cleared overrides");
        assert!(cleared_doc.peer_overrides.is_empty());
        assert_eq!(effective_policy, PeerPolicy::default());
    }

    #[tokio::test]
    async fn onboarding_import_writes_final_profile_and_share_vault() {
        let paths = test_paths("onboarding-import");
        paths.ensure().expect("ensure shell paths");
        replace_relay_profile(
            &paths,
            RelayProfile {
                id: "local".to_string(),
                label: "Local".to_string(),
                relays: vec!["ws://127.0.0.1:8194".to_string()],
            },
        )
        .expect("write relay profile");

        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group = bundle.group.clone();
        let share = bundle
            .shares
            .iter()
            .find(|share| share.idx == 2)
            .cloned()
            .expect("bob share");
        let inviter = group
            .members
            .iter()
            .find(|member| member.idx == 1)
            .expect("alice member");
        let package = OnboardingPackage {
            share: share.clone(),
            peer_pk: inviter.pubkey[1..].try_into().expect("xonly inviter"),
            relays: vec!["ws://127.0.0.1:8194".to_string()],
            challenge: Some([7u8; 32]),
            created_at: Some(10),
            expires_at: Some(20),
        };
        let encoded = encode_onboarding_package(&package, "test-password").expect("encode");
        let onboarding_nonce = bifrost_core::types::DerivedPublicNonce {
            binder_pn: [4u8; 33],
            hidden_pn: [5u8; 33],
            code: [6u8; 32],
        };
        let mut onboarding_state = DeviceState::new(share.idx, share.seckey);
        onboarding_state
            .nonce_pool
            .store_incoming(1, vec![onboarding_nonce.clone()]);
        onboarding_state
            .nonce_pool
            .generate_for_peer(1, 4)
            .expect("bootstrap outgoing");

        let result = import_profile_from_onboarding_value_with(
            &paths,
            &encoded,
            Some("Alice".to_string()),
            Some("local".to_string()),
            Some("vault-pass".to_string()),
            Some("test-password".to_string()),
            |_| async {
                Ok(BootstrapImportResult {
                    request_id: "req-1".to_string(),
                    group: group.clone(),
                    share: share.clone(),
                    relays: vec!["ws://127.0.0.1:8194".to_string()],
                    peer_pubkey: hex::encode(&inviter.pubkey[1..]),
                    challenge: Some([7u8; 32]),
                    group_member_count: group.members.len(),
                    bootstrap_nonces: vec![onboarding_nonce.clone()],
                    bootstrap_state: bifrost_app::onboarding::BootstrapStateSnapshot {
                        device_state_hex: hex::encode(
                            bincode::serialize(&onboarding_state).expect("serialize bootstrap state")
                        ),
                    },
                })
            },
        )
        .await
        .expect("import onboarding");

        let ProfileImportResult::ProfileCreated {
            profile,
            vault_record,
            ..
        } = result
        else {
            panic!("expected final profile import result");
        };

        assert_eq!(profile.share_ref, vault_record.id);
        assert!(Path::new(&profile.group_ref).exists());
        let share_raw = load_share_payload_with_passphrase(&paths, &profile, Some("vault-pass".to_string()))
            .expect("decrypt share payload");
        let parsed_share = parse_share_package(&share_raw).expect("parse stored share");
        assert_eq!(parsed_share.idx, share.idx);
        assert!(read_vault_record(&paths, &vault_record.id).is_ok());
        let store = bifrost_app::runtime::EncryptedFileStore::new(PathBuf::from(&profile.state_path), share.clone());
        let state = store.load().expect("load saved onboarding state");
        let peer_stats = state.nonce_pool.peer_stats(1);
        assert_eq!(peer_stats.incoming_available, 1);
        assert!(peer_stats.outgoing_available >= 4);

        unsafe {
            std::env::set_var(VAULT_ENV_PASSPHRASE, "vault-pass");
        }
        let (_resolved_profile, resolved) =
            resolve_profile_runtime(&paths, &profile.id).expect("resolve runtime");
        unsafe {
            std::env::remove_var(VAULT_ENV_PASSPHRASE);
        }
        let signer = bifrost_app::runtime::load_or_init_signer_resolved(&resolved, &store)
            .expect("load onboarding signer");
        let runtime_peer_stats = signer.state().nonce_pool.peer_stats(1);
        assert_eq!(runtime_peer_stats.incoming_available, 1);
        assert!(runtime_peer_stats.outgoing_available >= 4);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_invite_lifecycle_round_trip() {
        let paths = test_paths("daemon-invite-lifecycle");
        paths.ensure().expect("ensure shell paths");
        unsafe {
            std::env::set_var(VAULT_ENV_PASSPHRASE, "vault-pass");
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test port");
        let relay_port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let relay_url = format!("ws://127.0.0.1:{relay_port}");

        let relay = NostrRelay::new("127.0.0.1", relay_port, None);
        let relay_task = tokio::spawn(async move {
            let _ = relay.start().await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        replace_relay_profile(
            &paths,
            RelayProfile {
                id: "local".to_string(),
                label: "Local".to_string(),
                relays: vec![relay_url.clone()],
            },
        )
        .expect("write relay profile");

        let bundle = create_keyset(CreateKeysetConfig {
            threshold: 2,
            count: 3,
        })
        .expect("create keyset");
        let group_path = paths.data_dir.join("group.json");
        let share_path = paths.data_dir.join("share.json");
        write_json(&group_path, &GroupPackageWire::from(bundle.group.clone())).expect("write group");
        write_json(&share_path, &SharePackageWire::from(bundle.shares[0].clone())).expect("write share");

        let import = import_profile_from_files(
            &paths,
            &group_path,
            &share_path,
            Some("Alice".to_string()),
            Some("local".to_string()),
            Some("vault-pass".to_string()),
        )
        .expect("import profile");
        let ProfileImportResult::ProfileCreated { profile, .. } = import else {
            panic!("expected profile created");
        };

        let transport = build_daemon_transport(&profile);
        let metadata = DaemonMetadata {
            profile_id: profile.id.clone(),
            pid: std::process::id(),
            socket_path: transport.socket_path.display().to_string(),
            token: transport.token.clone(),
            log_path: paths.daemon_log_path(&profile.id).display().to_string(),
            started_at: now_unix_secs(),
        };
        write_daemon_metadata(&paths, &profile.id, &metadata).expect("write daemon metadata");

        let (_, resolved) = resolve_profile_runtime(&paths, &profile.id).expect("resolve profile runtime");
        let daemon_task = tokio::spawn(async move {
            let _ = run_resolved_daemon(resolved, transport).await;
        });

        let mut ready = false;
        for _ in 0..50 {
            if daemon_runtime_query(&paths, &profile.id, ControlCommand::RuntimeMetadata)
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ready, "daemon did not become ready");

        let created = daemon_runtime_query(
            &paths,
            &profile.id,
            ControlCommand::InviteCreate {
                relay_overrides: Vec::new(),
                expires_in_secs: 60,
                label: Some("test-invite".to_string()),
            },
        )
        .await
        .expect("create invite");
        let token = created
            .get("token")
            .and_then(Value::as_str)
            .expect("invite token");
        assert!(!token.is_empty());

        let listed = daemon_runtime_query(&paths, &profile.id, ControlCommand::InviteList)
            .await
            .expect("list invites");
        let invites = listed.as_array().expect("invite array");
        assert_eq!(invites.len(), 1);
        let challenge = invites[0]
            .get("challenge_hex")
            .and_then(Value::as_str)
            .expect("challenge hex")
            .to_string();

        let revoked = daemon_runtime_query(
            &paths,
            &profile.id,
            ControlCommand::InviteRevoke {
                challenge_hex32: challenge.clone(),
            },
        )
        .await
        .expect("revoke invite");
        assert_eq!(
            revoked.get("challenge_hex32").and_then(Value::as_str),
            Some(challenge.as_str())
        );

        let listed_after = daemon_runtime_query(&paths, &profile.id, ControlCommand::InviteList)
            .await
            .expect("list invites after revoke");
        assert_eq!(listed_after.as_array().expect("invite array").len(), 0);

        let _ = stop_profile_daemon(&paths, &profile.id).await.expect("stop daemon");
        let _ = tokio::time::timeout(Duration::from_secs(5), daemon_task).await;
        relay_task.abort();
        unsafe {
            std::env::remove_var(VAULT_ENV_PASSPHRASE);
        }
    }
}
