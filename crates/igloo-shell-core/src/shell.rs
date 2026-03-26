use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use argon2::Argon2;
use bifrost_app::host::{ControlCommand, DaemonClient, DaemonTransportConfig};
use bifrost_app::onboarding::{
    BootstrapImportResult, BootstrapValidationReport, complete_onboarding_package,
    persist_validated_onboarding_state,
};
use bifrost_app::runtime::{AppOptions, ResolvedAppConfig};
use bifrost_codec::{
    parse_group_package, parse_share_package, wire::GroupPackageWire, wire::SharePackageWire,
};
use bifrost_core::get_group_id;
use bifrost_core::types::{PeerPolicy, PeerPolicyOverride, PolicyOverrideValue};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use frostr_utils::{
    BfManualPeerPolicyOverride, BfOnboardPayload, BfProfileDevice, BfProfilePayload,
    BfRemotePeerPolicyObservation, BfSharePayload, CreateKeysetConfig,
    PROFILE_BACKUP_EVENT_KIND, RotateKeysetRequest, bf_peer_scoped_policy_profile_to_core,
    build_profile_backup_event, core_peer_policy_override_to_bf, create_encrypted_profile_backup,
    create_keyset, decode_bfonboard_package, decode_bfprofile_package, decode_bfshare_package,
    derive_profile_id_from_share_secret, encode_bfonboard_package, encode_bfprofile_package,
    encode_bfshare_package, parse_profile_backup_event, rotate_keyset_dealer,
};
use futures_util::{SinkExt, StreamExt};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use nostr::Event;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use tokio::time::{Duration as TokioDuration, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

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
    pub rotations_dir: PathBuf,
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
            rotations_dir: state_dir.join("rotations"),
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
            &self.rotations_dir,
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
    #[serde(default)]
    pub remote_policy_observations: Value,
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
    default_override: Option<PeerPolicyOverride>,
    #[serde(default)]
    peer_overrides: Vec<PolicyOverrideEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyOverrideEntry {
    pubkey: String,
    #[serde(default)]
    policy_override: PeerPolicyOverride,
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

#[derive(Debug, Clone, Serialize)]
pub struct ProfilePackageExportResult {
    pub profile_id: String,
    pub format: String,
    pub out_path: Option<String>,
    pub package: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileBackupPublishResult {
    pub profile_id: String,
    pub relays: Vec<String>,
    pub event_id: String,
    pub author_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedOnboardingImport {
    pub id: String,
    pub vault_record_id: String,
    pub label: Option<String>,
    pub relay_profile: String,
    pub peer_pubkey: String,
    pub relays: Vec<String>,
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

#[derive(Debug, Clone)]
pub struct ProfilePreview {
    pub profile_id: String,
    pub label: String,
    pub share_public_key: String,
    pub group_public_key: String,
    pub threshold: usize,
    pub total_count: usize,
    pub relays: Vec<String>,
    pub peer_pubkey: Option<String>,
    pub source: &'static str,
}

#[derive(Debug, Clone)]
pub struct ConnectedOnboardingImport {
    pub preview: ProfilePreview,
    pub completion: BootstrapImportResult,
}

#[derive(Debug, Clone)]
pub struct GeneratedShareDraft {
    pub member_idx: u16,
    pub label: String,
    pub share_public_key: String,
}

#[derive(Debug, Clone)]
pub struct GeneratedKeysetDraft {
    pub keyset_name: String,
    pub threshold: u16,
    pub count: u16,
    pub group_public_key: String,
    pub shares: Vec<GeneratedShareDraft>,
    group: bifrost_core::types::GroupPackage,
    share_packages: Vec<bifrost_core::types::SharePackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationWorkspaceSource {
    pub package_path: String,
    #[serde(default)]
    pub package_secret_env: Option<String>,
    #[serde(default)]
    pub package_secret_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationTargetMode {
    LocalReplace,
    Bfonboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationUsageHint {
    NewDevice,
    RotateExistingDevice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationWorkspaceTarget {
    pub member_index: u16,
    pub mode: RotationTargetMode,
    pub label: String,
    pub relays: Vec<String>,
    #[serde(default)]
    pub usage_hint: Option<RotationUsageHint>,
    #[serde(default)]
    pub replace_profile_id: Option<String>,
    #[serde(default)]
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationWorkspaceDocument {
    pub version: u32,
    pub source_profile_id: String,
    pub source_group_id: String,
    pub source_group_public_key: String,
    pub source_keyset_name: String,
    pub source_threshold: u16,
    pub source_count: u16,
    pub next_threshold: u16,
    pub next_count: u16,
    pub source_packages: Vec<RotationWorkspaceSource>,
    pub targets: Vec<RotationWorkspaceTarget>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotationWorkspaceStatus {
    pub workspace_path: String,
    pub ready: bool,
    pub source_profile_id: String,
    pub source_group_id: String,
    pub source_group_public_key: String,
    pub source_threshold: u16,
    pub next_threshold: u16,
    pub next_count: u16,
    pub source_packages_present: usize,
    pub source_packages_required: usize,
    pub local_target_member_index: Option<u16>,
    pub local_replace_profile_id: Option<String>,
    pub remote_target_count: usize,
    pub missing_secret_entries: Vec<String>,
    pub validation_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotationGeneratedPackage {
    pub member_index: u16,
    pub label: String,
    pub profile_id: String,
    pub usage_hint: RotationUsageHint,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotationGenerateResult {
    pub workspace_path: String,
    pub source_group_id: String,
    pub next_group_id: String,
    pub replaced_profile_id: String,
    pub profile: ProfileManifest,
    pub generated_packages: Vec<RotationGeneratedPackage>,
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
        fs::remove_dir_all(&state_dir)
            .with_context(|| format!("remove {}", state_dir.display()))?;
    }

    if is_managed_group_path(paths, &profile.group_ref)
        && !is_group_ref_in_use(paths, &profile.id, &profile.group_ref)?
        && Path::new(&profile.group_ref).exists()
    {
        fs::remove_file(&profile.group_ref)
            .with_context(|| format!("remove {}", profile.group_ref))?;
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

pub fn doctor_profile(
    paths: &ShellPaths,
    profile: &ProfileManifest,
) -> Result<ProfileDoctorReport> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDirection {
    Request,
    Respond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMethod {
    Ping,
    Onboard,
    Sign,
    Ecdh,
}

fn policy_field_mut(
    policy: &mut PeerPolicyOverride,
    direction: PolicyDirection,
    method: PolicyMethod,
) -> &mut PolicyOverrideValue {
    let branch = match direction {
        PolicyDirection::Request => &mut policy.request,
        PolicyDirection::Respond => &mut policy.respond,
    };
    match method {
        PolicyMethod::Ping => &mut branch.ping,
        PolicyMethod::Onboard => &mut branch.onboard,
        PolicyMethod::Sign => &mut branch.sign,
        PolicyMethod::Ecdh => &mut branch.ecdh,
    }
}

fn merge_policy_override(
    base: &PeerPolicyOverride,
    next: &PeerPolicyOverride,
) -> PeerPolicyOverride {
    fn resolve(base: PolicyOverrideValue, next: PolicyOverrideValue) -> PolicyOverrideValue {
        match next {
            PolicyOverrideValue::Unset => base,
            other => other,
        }
    }

    PeerPolicyOverride {
        request: bifrost_core::types::MethodPolicyOverride {
            echo: resolve(base.request.echo, next.request.echo),
            ping: resolve(base.request.ping, next.request.ping),
            onboard: resolve(base.request.onboard, next.request.onboard),
            sign: resolve(base.request.sign, next.request.sign),
            ecdh: resolve(base.request.ecdh, next.request.ecdh),
        },
        respond: bifrost_core::types::MethodPolicyOverride {
            echo: resolve(base.respond.echo, next.respond.echo),
            ping: resolve(base.respond.ping, next.respond.ping),
            onboard: resolve(base.respond.onboard, next.respond.onboard),
            sign: resolve(base.respond.sign, next.respond.sign),
            ecdh: resolve(base.respond.ecdh, next.respond.ecdh),
        },
    }
}

fn is_empty_policy_override(policy: &PeerPolicyOverride) -> bool {
    let unset = PolicyOverrideValue::Unset;
    [
        policy.request.echo,
        policy.request.ping,
        policy.request.onboard,
        policy.request.sign,
        policy.request.ecdh,
        policy.respond.echo,
        policy.respond.ping,
        policy.respond.onboard,
        policy.respond.sign,
        policy.respond.ecdh,
    ]
    .into_iter()
    .all(|value| value == unset)
}

fn effective_policy_override(
    document: &PolicyOverridesDocument,
    peer_pubkey: &str,
) -> PeerPolicyOverride {
    let base = document.default_override.clone().unwrap_or_default();
    let specific = document
        .peer_overrides
        .iter()
        .find(|entry| entry.pubkey == peer_pubkey)
        .map(|entry| entry.policy_override.clone())
        .unwrap_or_default();
    merge_policy_override(&base, &specific)
}

pub fn set_profile_default_policy_override(
    paths: &ShellPaths,
    profile_id: &str,
    direction: PolicyDirection,
    method: PolicyMethod,
    value: PolicyOverrideValue,
) -> Result<ProfileManifest> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    let mut policy = document.default_override.clone().unwrap_or_default();
    *policy_field_mut(&mut policy, direction, method) = value;
    document.default_override = if is_empty_policy_override(&policy) {
        None
    } else {
        Some(policy)
    };
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok(profile)
}

pub fn set_profile_peer_policy_override(
    paths: &ShellPaths,
    profile_id: &str,
    peer_pubkey: &str,
    direction: PolicyDirection,
    method: PolicyMethod,
    value: PolicyOverrideValue,
) -> Result<(ProfileManifest, PeerPolicyOverride)> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    if let Some(existing) = document
        .peer_overrides
        .iter_mut()
        .find(|entry| entry.pubkey == peer_pubkey)
    {
        *policy_field_mut(&mut existing.policy_override, direction, method) = value;
    } else {
        let mut policy_override = PeerPolicyOverride::default();
        *policy_field_mut(&mut policy_override, direction, method) = value;
        document.peer_overrides.push(PolicyOverrideEntry {
            pubkey: peer_pubkey.to_string(),
            policy_override,
        });
    }
    document
        .peer_overrides
        .retain(|entry| !is_empty_policy_override(&entry.policy_override));
    document
        .peer_overrides
        .sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    let effective_override = effective_policy_override(&document, peer_pubkey);
    profile.policy_overrides = serde_json::to_value(document)?;
    write_profile(paths, &profile)?;
    Ok((profile, effective_override))
}

pub fn clear_profile_peer_policy(
    paths: &ShellPaths,
    profile_id: &str,
    peer_pubkey: &str,
) -> Result<(ProfileManifest, PeerPolicyOverride)> {
    let mut profile = read_profile(paths, profile_id)?;
    let mut document = parse_policy_overrides_doc(profile.policy_overrides.clone())?;
    document
        .peer_overrides
        .retain(|entry| entry.pubkey != peer_pubkey);
    let effective_policy = effective_policy_override(&document, peer_pubkey);
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
    let (peers, manual_policy_overrides) =
        resolve_profile_peers_and_overrides(&group, &share, profile.policy_overrides.clone())
            .context("resolve peer policy overrides")?;
    let remote_policy_observations =
        parse_remote_policy_observations_doc(profile.remote_policy_observations.clone())
            .context("resolve remote policy observations")?;
    let options: AppOptions = if profile.runtime_options.is_null() {
        AppOptions::default()
    } else {
        serde_json::from_value(profile.runtime_options.clone()).context("parse runtime options")?
    };

    Ok((
        profile.clone(),
        ResolvedAppConfig {
            group,
            share,
            state_path: PathBuf::from(&profile.state_path),
            relays: relay_profile.relays,
            peers,
            manual_policy_overrides,
            remote_policy_observations,
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

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellCheckKind {
    Onboard,
    Sign,
    Ecdh,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellCheckResult {
    pub kind: ShellCheckKind,
    pub profile_id: String,
    pub ready: bool,
    pub reasons_not_ready: Vec<String>,
    pub runtime_online: bool,
    pub share_public_key: Option<String>,
    pub group_public_key: Option<String>,
    pub relay_urls: Vec<String>,
    pub relay_connected_count: usize,
    pub checked_at: u64,
    pub details: Value,
}

fn runtime_peers(status: &Value) -> &[Value] {
    status
        .get("peers")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn runtime_readiness(status: &Value) -> Value {
    status
        .get("readiness")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()))
}

fn peer_pubkeys_by<'a, F>(peers: &'a [Value], predicate: F) -> Vec<String>
where
    F: Fn(&'a Value) -> bool,
{
    peers
        .iter()
        .filter(|peer| predicate(peer))
        .filter_map(|peer| peer.get("pubkey").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
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
    let relays = probe_relays(&profile.relays).await;

    Ok(RelayConnectivityReport {
        relay_profile_id: profile.id,
        relays,
    })
}

pub async fn check_profile_runtime(
    paths: &ShellPaths,
    profile_id: &str,
    kind: ShellCheckKind,
) -> Result<ShellCheckResult> {
    let profile = read_profile(paths, profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;
    let relay_urls = relay_profile.relays.clone();
    let relays = probe_relays(&relay_urls).await;
    let relay_connected_count = relays.iter().filter(|relay| relay.ok).count();
    let checked_at = now_unix_secs();

    let runtime_status =
        daemon_runtime_query(paths, profile_id, ControlCommand::RuntimeStatus).await;
    let mut reasons_not_ready = Vec::new();
    let mut runtime_online = false;
    let mut share_public_key = None;
    let mut group_public_key = None;
    let mut details = serde_json::json!({
        "relay_probes": relays,
    });

    let status = match runtime_status {
        Ok(status) => {
            runtime_online = true;
            share_public_key = status
                .get("metadata")
                .and_then(|metadata| metadata.get("share_public_key"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            group_public_key = status
                .get("metadata")
                .and_then(|metadata| metadata.get("group_public_key"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            status
        }
        Err(err) => {
            reasons_not_ready.push("daemon_unreachable".to_string());
            details["daemon_error"] = Value::String(err.to_string());
            return Ok(ShellCheckResult {
                kind,
                profile_id: profile_id.to_string(),
                ready: false,
                reasons_not_ready,
                runtime_online,
                share_public_key,
                group_public_key,
                relay_urls,
                relay_connected_count,
                checked_at,
                details,
            });
        }
    };

    if share_public_key.is_none() {
        reasons_not_ready.push("missing_share_identity".to_string());
    }
    if group_public_key.is_none() {
        reasons_not_ready.push("missing_group_identity".to_string());
    }
    if relay_connected_count == 0 {
        reasons_not_ready.push("no_connected_relays".to_string());
    }

    let ready = match kind {
        ShellCheckKind::Onboard => {
            let restore_complete = status
                .get("readiness")
                .and_then(|readiness| readiness.get("restore_complete"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let peer_callback_ready = share_public_key.is_some() && group_public_key.is_some();
            let online_peer_count = status
                .get("peers")
                .and_then(Value::as_array)
                .map(|peers| {
                    peers
                        .iter()
                        .filter(|peer| peer.get("online").and_then(Value::as_bool).unwrap_or(false))
                        .count()
                })
                .unwrap_or(0);
            let known_peer_count = status
                .get("status")
                .and_then(|device_status| device_status.get("known_peers"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let degraded_reasons = status
                .get("readiness")
                .and_then(|readiness| readiness.get("degraded_reasons"))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            details["restore_complete"] = Value::Bool(restore_complete);
            details["peer_callback_ready"] = Value::Bool(peer_callback_ready);
            details["known_peer_count"] = Value::Number(known_peer_count.into());
            details["online_peer_count"] = Value::Number((online_peer_count as u64).into());
            details["degraded_reasons"] = degraded_reasons;
            reasons_not_ready.is_empty() && runtime_online && peer_callback_ready
        }
        ShellCheckKind::Sign => {
            let readiness = runtime_readiness(&status);
            let peers = runtime_peers(&status);
            let sign_ready = readiness
                .get("sign_ready")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let threshold = readiness
                .get("threshold")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let sign_responder_peers = peer_pubkeys_by(peers, |peer| {
                peer.get("online").and_then(Value::as_bool).unwrap_or(false)
                    && peer
                        .get("outgoing_available")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        > 0
            });
            let sign_initiator_peers = peer_pubkeys_by(peers, |peer| {
                peer.get("can_sign")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            });
            let all_peer_pubkeys = peer_pubkeys_by(peers, |_| true);
            let missing_initiators = all_peer_pubkeys
                .iter()
                .filter(|pubkey| !sign_initiator_peers.contains(pubkey))
                .cloned()
                .collect::<Vec<_>>();
            let missing_responders = all_peer_pubkeys
                .iter()
                .filter(|pubkey| !sign_responder_peers.contains(pubkey))
                .cloned()
                .collect::<Vec<_>>();
            let restore_complete = readiness
                .get("restore_complete")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let degraded_reasons = readiness
                .get("degraded_reasons")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            let sign_responder_ready = sign_responder_peers.len() >= threshold;

            if !restore_complete {
                reasons_not_ready.push("restore_incomplete".to_string());
            }
            if !sign_ready || !sign_responder_ready {
                reasons_not_ready.push("insufficient_signing_peers".to_string());
            }
            if degraded_reasons
                .as_array()
                .is_some_and(|reasons| !reasons.is_empty())
            {
                reasons_not_ready.push("runtime_degraded".to_string());
            }

            details["readiness"] = readiness;
            details["sign_initiator_peer_count"] =
                Value::Number((sign_initiator_peers.len() as u64).into());
            details["sign_responder_peer_count"] =
                Value::Number((sign_responder_peers.len() as u64).into());
            details["sign_initiator_peers"] = serde_json::json!(sign_initiator_peers);
            details["sign_responder_peers"] = serde_json::json!(sign_responder_peers);
            details["missing_sign_initiator_peers"] = serde_json::json!(missing_initiators);
            details["missing_sign_responder_peers"] = serde_json::json!(missing_responders);
            reasons_not_ready.is_empty()
        }
        ShellCheckKind::Ecdh => {
            let readiness = runtime_readiness(&status);
            let peers = runtime_peers(&status);
            let ecdh_ready = readiness
                .get("ecdh_ready")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let ecdh_ready_peers = peer_pubkeys_by(peers, |peer| {
                peer.get("online").and_then(Value::as_bool).unwrap_or(false)
            });
            let all_peer_pubkeys = peer_pubkeys_by(peers, |_| true);
            let missing_ecdh = all_peer_pubkeys
                .iter()
                .filter(|pubkey| !ecdh_ready_peers.contains(pubkey))
                .cloned()
                .collect::<Vec<_>>();
            let restore_complete = readiness
                .get("restore_complete")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let degraded_reasons = readiness
                .get("degraded_reasons")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));

            if !restore_complete {
                reasons_not_ready.push("restore_incomplete".to_string());
            }
            if !ecdh_ready {
                reasons_not_ready.push("insufficient_ecdh_peers".to_string());
            }
            if degraded_reasons
                .as_array()
                .is_some_and(|reasons| !reasons.is_empty())
            {
                reasons_not_ready.push("runtime_degraded".to_string());
            }

            details["readiness"] = readiness;
            details["ecdh_peer_count"] = Value::Number((ecdh_ready_peers.len() as u64).into());
            details["ecdh_ready_peers"] = serde_json::json!(ecdh_ready_peers);
            details["missing_ecdh_peers"] = serde_json::json!(missing_ecdh);
            reasons_not_ready.is_empty()
        }
    };

    Ok(ShellCheckResult {
        kind,
        profile_id: profile_id.to_string(),
        ready,
        reasons_not_ready,
        runtime_online,
        share_public_key,
        group_public_key,
        relay_urls,
        relay_connected_count,
        checked_at,
        details,
    })
}

#[cfg(unix)]
pub async fn start_profile_daemon_with_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    vault_passphrase: Option<String>,
) -> Result<DaemonMetadata> {
    paths.ensure()?;
    let profile = read_profile(paths, profile_id)?;
    validate_profile_unlock(paths, &profile, vault_passphrase.clone())?;
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
    let mut command = Command::new(exe);
    command
        .arg("__daemon-run")
        .arg("--profile")
        .arg(profile_id)
        .arg("--socket-path")
        .arg(&transport.socket_path)
        .arg("--token")
        .arg(&transport.token)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(passphrase) = &vault_passphrase {
        command.env(VAULT_ENV_PASSPHRASE, passphrase);
    }
    let mut child = command.spawn().context("spawn igloo-shell daemon")?;

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

    if let Ok(None) = child.try_wait() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = remove_daemon_metadata(paths, profile_id);

    Err(anyhow!(
        "daemon did not become ready for profile {profile_id}: {}",
        last_error.unwrap_or_else(|| "unknown startup failure".to_string())
    ))
}

#[cfg(unix)]
pub async fn start_profile_daemon(paths: &ShellPaths, profile_id: &str) -> Result<DaemonMetadata> {
    start_profile_daemon_with_passphrase(paths, profile_id, None).await
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
    let share_secret_hex = hex::encode(share.seckey);
    let profile_id = derive_profile_id_for_share_secret(&share_secret_hex)?;
    ensure_profile_id_unused(paths, &profile_id)?;

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
    let decoded = decode_bfonboard_package(&package_raw, password.as_str())
        .context("decode bfonboard package")?;
    let relay_profile_id =
        relay_profile.unwrap_or_else(|| format!("onboarding-{}", now_unix_secs()));
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

pub async fn connect_onboarding_package_preview(
    package_raw: &str,
    onboarding_password: String,
) -> Result<ConnectedOnboardingImport> {
    let decoded = decode_bfonboard_package(package_raw, onboarding_password.as_str())
        .context("decode bfonboard package")?;
    let completion = complete_onboarding_package(decoded, Duration::from_secs(30)).await?;
    let preview = preview_from_bootstrap_completion(
        &completion,
        None,
        "bfonboard",
        Some(completion.peer_pubkey.clone()),
    )?;
    Ok(ConnectedOnboardingImport {
        preview,
        completion,
    })
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
    F: FnOnce(BfOnboardPayload) -> Fut,
    Fut: std::future::Future<Output = Result<BootstrapImportResult>>,
{
    paths.ensure()?;
    let vault_passphrase_for_share = vault_passphrase.clone();
    let password = resolve_secret(
        onboarding_password,
        ONBOARDING_ENV_PASSPHRASE,
        "onboarding package password",
    )?;
    let decoded = decode_bfonboard_package(&package_raw, password.as_str())
        .context("decode bfonboard package")?;
    let relay_profile_id =
        ensure_onboarding_relay_profile(paths, relay_profile, label.as_deref(), &decoded.relays)?;
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
        "bfonboard_import",
        &share_raw,
        vault_passphrase_for_share,
    )?;
    let _ = remove_vault_record(paths, &vault_record.id);

    finalize_onboarding_import(paths, completion, label, relay_profile_id, share_record)
}

pub fn preview_bfprofile_value(
    package_raw: &str,
    package_password: String,
    label: Option<String>,
) -> Result<(ProfilePreview, BfProfilePayload)> {
    let payload = decode_bfprofile_package(package_raw, &package_password)
        .context("decode bfprofile package")?;
    let preview = preview_from_profile_payload(&payload, label, "bfprofile")?;
    Ok((preview, payload))
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

pub fn import_profile_from_bfprofile_value(
    paths: &ShellPaths,
    package_raw: &str,
    package_password: String,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    let payload = decode_bfprofile_package(package_raw, &package_password)
        .context("decode bfprofile package")?;
    import_profile_from_bfprofile_payload(paths, payload, label, relay_profile, vault_passphrase)
}

pub async fn preview_bfshare_recovery(
    package_raw: &str,
    package_password: String,
    label: Option<String>,
) -> Result<(ProfilePreview, BfProfilePayload)> {
    let share =
        decode_bfshare_package(package_raw, &package_password).context("decode bfshare package")?;
    let author_pubkey = derive_member_pubkey_hex(hex_to_bytes32(&share.share_secret)?)?;
    let event =
        fetch_latest_nostr_event(&share.relays, &author_pubkey, PROFILE_BACKUP_EVENT_KIND).await?;
    let backup = parse_profile_backup_event(&event, &share.share_secret)
        .context("parse encrypted profile backup")?;
    let payload = BfProfilePayload {
        profile_id: derive_profile_id_for_share_secret(&share.share_secret)?,
        version: backup.version,
        keyset_name: backup.keyset_name,
        device: BfProfileDevice {
            name: label.clone().unwrap_or_else(|| backup.device.name.clone()),
            share_secret: share.share_secret,
            manual_peer_policy_overrides: backup.device.manual_peer_policy_overrides,
            remote_peer_policy_observations: backup.device.remote_peer_policy_observations,
            relays: backup.device.relays,
        },
        group_package: backup.group_package,
    };
    let preview = preview_from_profile_payload(&payload, label, "bfshare")?;
    Ok((preview, payload))
}

pub fn export_profile_as_bfprofile(
    paths: &ShellPaths,
    profile_id: &str,
    package_password: String,
    vault_passphrase: Option<String>,
    out_path: Option<&Path>,
) -> Result<ProfilePackageExportResult> {
    let payload = profile_to_package_payload(paths, profile_id, vault_passphrase)?;
    let package = encode_bfprofile_package(&payload, &package_password)
        .context("encode bfprofile package")?;
    write_package_output(out_path, &package)?;
    Ok(ProfilePackageExportResult {
        profile_id: profile_id.to_string(),
        format: "bfprofile".to_string(),
        out_path: out_path.map(|path| path.display().to_string()),
        package,
    })
}

pub fn export_profile_as_bfshare(
    paths: &ShellPaths,
    profile_id: &str,
    package_password: String,
    vault_passphrase: Option<String>,
    out_path: Option<&Path>,
) -> Result<ProfilePackageExportResult> {
    let payload = profile_to_package_payload(paths, profile_id, vault_passphrase)?;
    let package = encode_bfshare_package(
        &BfSharePayload {
            share_secret: payload.device.share_secret,
            relays: payload.device.relays,
        },
        &package_password,
    )
    .context("encode bfshare package")?;
    write_package_output(out_path, &package)?;
    Ok(ProfilePackageExportResult {
        profile_id: profile_id.to_string(),
        format: "bfshare".to_string(),
        out_path: out_path.map(|path| path.display().to_string()),
        package,
    })
}

pub fn export_profile_as_bfonboard(
    paths: &ShellPaths,
    profile_id: &str,
    recipient_share_path: &Path,
    relay_urls: Option<Vec<String>>,
    package_password: String,
    vault_passphrase: Option<String>,
    out_path: Option<&Path>,
) -> Result<ProfilePackageExportResult> {
    let payload = profile_to_package_payload(paths, profile_id, vault_passphrase)?;
    let recipient_share_raw = fs::read_to_string(recipient_share_path)
        .with_context(|| format!("read {}", recipient_share_path.display()))?;
    let recipient_share =
        parse_share_package(&recipient_share_raw).context("parse recipient share")?;
    let relays = relay_urls
        .unwrap_or(payload.device.relays)
        .into_iter()
        .map(|relay| relay.trim().to_string())
        .filter(|relay| !relay.is_empty())
        .collect::<Vec<_>>();
    if relays.is_empty() {
        bail!("bfonboard export requires at least one relay url");
    }
    let package = encode_bfonboard_package(
        &BfOnboardPayload {
            share_secret: hex::encode(recipient_share.seckey),
            relays,
            peer_pk: derive_member_pubkey_hex(hex_to_bytes32(&payload.device.share_secret)?)?,
        },
        &package_password,
    )
    .context("encode bfonboard package")?;
    write_package_output(out_path, &package)?;
    Ok(ProfilePackageExportResult {
        profile_id: profile_id.to_string(),
        format: "bfonboard".to_string(),
        out_path: out_path.map(|path| path.display().to_string()),
        package,
    })
}

pub async fn publish_profile_backup(
    paths: &ShellPaths,
    profile_id: &str,
    vault_passphrase: Option<String>,
) -> Result<ProfileBackupPublishResult> {
    let payload = profile_to_package_payload(paths, profile_id, vault_passphrase)?;
    let backup = create_encrypted_profile_backup(&payload).context("build encrypted backup")?;
    let event = build_profile_backup_event(&payload.device.share_secret, &backup, None)
        .context("build backup event")?;
    publish_nostr_event(&payload.device.relays, &event).await?;
    Ok(ProfileBackupPublishResult {
        profile_id: profile_id.to_string(),
        relays: payload.device.relays,
        event_id: event.id.to_hex(),
        author_pubkey: event.pubkey.to_string(),
    })
}

pub async fn recover_profile_from_bfshare_value(
    paths: &ShellPaths,
    package_raw: &str,
    package_password: String,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    let share =
        decode_bfshare_package(package_raw, &package_password).context("decode bfshare package")?;
    let author_pubkey = derive_member_pubkey_hex(hex_to_bytes32(&share.share_secret)?)?;
    let event =
        fetch_latest_nostr_event(&share.relays, &author_pubkey, PROFILE_BACKUP_EVENT_KIND).await?;
    let backup = parse_profile_backup_event(&event, &share.share_secret)
        .context("parse encrypted profile backup")?;
    let payload = BfProfilePayload {
        profile_id: derive_profile_id_for_share_secret(&share.share_secret)?,
        version: backup.version,
        keyset_name: backup.keyset_name,
        device: BfProfileDevice {
            name: label.unwrap_or_else(|| backup.device.name.clone()),
            share_secret: share.share_secret,
            manual_peer_policy_overrides: backup.device.manual_peer_policy_overrides,
            remote_peer_policy_observations: backup.device.remote_peer_policy_observations,
            relays: backup.device.relays,
        },
        group_package: backup.group_package,
    };
    import_profile_from_bfprofile_payload(paths, payload, None, relay_profile, vault_passphrase)
}

pub fn finalize_rotation_update_import(
    paths: &ShellPaths,
    target: &ProfileManifest,
    target_payload: BfProfilePayload,
    rotated_group: &bifrost_core::types::GroupPackage,
    rotated_payload: BfProfilePayload,
    vault_passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    if hex::encode(rotated_group.group_pk) != hex::encode(group_from_payload(&target_payload)?.group_pk) {
        bail!("rotation update does not match the selected profile group public key");
    }
    if rotated_payload.profile_id == target_payload.profile_id {
        bail!("rotation update did not produce a new device profile id");
    }

    paths.ensure()?;
    let share = bifrost_core::types::SharePackage {
        idx: find_member_index_for_share_secret(rotated_group, &rotated_payload.device.share_secret)?,
        seckey: hex_to_bytes32(&rotated_payload.device.share_secret)?,
    };
    let relay_profile_id = ensure_onboarding_relay_profile(
        paths,
        Some(target.relay_profile.clone()),
        Some(target.label.as_str()),
        &rotated_payload.device.relays,
    )?;
    let now = now_unix_secs();
    let group_ref = store_group_package(paths, rotated_group)?;
    let share_raw = serde_json::to_string_pretty(&SharePackageWire::from(share.clone()))
        .context("serialize rotated share package")?;
    let vault_record = store_secret_payload(
        paths,
        "share_package",
        "rotation_update",
        &share_raw,
        vault_passphrase,
    )?;
    let mut migrated = build_profile_manifest(
        paths,
        &rotated_payload.profile_id,
        target.label.clone(),
        group_ref,
        vault_record.id.clone(),
        relay_profile_id,
        now,
    );
    migrated.policy_overrides =
        build_policy_overrides_value(&rotated_payload.device.manual_peer_policy_overrides)?;
    migrated.remote_policy_observations =
        build_remote_policy_observations_value(&rotated_payload.device.remote_peer_policy_observations)?;
    migrated.runtime_options = target.runtime_options.clone();
    migrated.last_used_at = target.last_used_at;
    fs::create_dir_all(paths.profile_state_dir(&migrated.id))
        .with_context(|| format!("create {}", paths.profile_state_dir(&migrated.id).display()))?;
    write_profile(paths, &migrated)?;

    remove_profile(paths, &target.id)?;
    touch_last_used_profile(paths, &migrated.id)?;

    Ok(ProfileImportResult::ProfileCreated {
        profile: migrated,
        vault_record,
        diagnostics: None,
        warnings: Vec::new(),
    })
}

pub async fn apply_rotation_update_from_bfonboard_value(
    paths: &ShellPaths,
    target_profile_id: &str,
    package_raw: &str,
    onboarding_password: String,
    vault_passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    let target = read_profile(paths, target_profile_id)?;
    let target_payload =
        profile_to_package_payload(paths, target_profile_id, vault_passphrase.clone())?;
    let connection = connect_onboarding_package_preview(package_raw, onboarding_password).await?;

    if connection.preview.group_public_key != hex::encode(group_from_payload(&target_payload)?.group_pk) {
        bail!("rotation update does not match the selected profile group public key");
    }
    if connection.preview.profile_id == target_payload.profile_id {
        bail!("rotation update did not produce a new device profile id");
    }

    let rotated_payload = BfProfilePayload {
        profile_id: connection.preview.profile_id.clone(),
        version: 1,
        keyset_name: target_payload.keyset_name.clone(),
        device: BfProfileDevice {
            name: target.label.clone(),
            share_secret: hex::encode(connection.completion.share.seckey),
            manual_peer_policy_overrides: Vec::new(),
            remote_peer_policy_observations: Vec::new(),
            relays: connection.completion.relays.clone(),
        },
        group_package: GroupPackageWire::from(connection.completion.group.clone()),
    };

    finalize_rotation_update_import(
        paths,
        &target,
        target_payload,
        &connection.completion.group,
        rotated_payload,
        vault_passphrase,
    )
}

pub fn default_rotation_workspace_path(paths: &ShellPaths, source_profile_id: &str) -> PathBuf {
    paths.rotations_dir.join(format!(
        "{}-{}",
        source_profile_id,
        now_unix_secs()
    ))
}

pub fn create_rotation_workspace(
    paths: &ShellPaths,
    source_profile_id: &str,
    threshold: u16,
    count: u16,
    workspace_root: &Path,
    source_package_paths: Vec<String>,
    vault_passphrase: Option<String>,
) -> Result<RotationWorkspaceDocument> {
    paths.ensure()?;
    create_keyset(CreateKeysetConfig { threshold, count })
        .map_err(|error| anyhow!("validate rotation geometry: {error}"))?;

    let source_profile = read_profile(paths, source_profile_id)?;
    let source_payload = profile_to_package_payload(paths, source_profile_id, vault_passphrase)?;
    let source_group = group_from_payload(&source_payload)?;
    let source_share = share_from_payload(&source_group, &source_payload)?;
    let source_group_id = hex::encode(get_group_id(&source_group).context("derive source group id")?);
    let source_keyset_name = source_payload.keyset_name.clone();

    if workspace_root.exists() {
        bail!("rotation workspace already exists at {}", workspace_root.display());
    }

    let targets = (1..=count)
        .map(|member_index| RotationWorkspaceTarget {
            member_index,
            mode: if member_index == source_share.idx {
                RotationTargetMode::LocalReplace
            } else {
                RotationTargetMode::Bfonboard
            },
            label: if member_index == source_share.idx {
                source_profile.label.clone()
            } else {
                format!("{source_keyset_name} Device {member_index}")
            },
            relays: source_payload.device.relays.clone(),
            usage_hint: if member_index == source_share.idx {
                None
            } else {
                Some(RotationUsageHint::RotateExistingDevice)
            },
            replace_profile_id: if member_index == source_share.idx {
                Some(source_profile_id.to_string())
            } else {
                None
            },
            output_path: if member_index == source_share.idx {
                None
            } else {
                Some(
                    workspace_root
                        .join("packages")
                        .join(format!("member-{member_index}.bfonboard.txt"))
                        .display()
                        .to_string(),
                )
            },
        })
        .collect::<Vec<_>>();

    let document = RotationWorkspaceDocument {
        version: 1,
        source_profile_id: source_profile_id.to_string(),
        source_group_id,
        source_group_public_key: hex::encode(source_group.group_pk),
        source_keyset_name,
        source_threshold: source_group.threshold,
        source_count: source_group.members.len() as u16,
        next_threshold: threshold,
        next_count: count,
        source_packages: source_package_paths
            .into_iter()
            .map(|package_path| RotationWorkspaceSource {
                package_path,
                package_secret_env: None,
                package_secret_file: None,
            })
            .collect(),
        targets,
    };
    write_rotation_workspace(workspace_root, &document)?;
    Ok(document)
}

pub fn load_rotation_workspace(workspace_root: &Path) -> Result<RotationWorkspaceDocument> {
    read_json(&rotation_workspace_manifest_path(workspace_root))
}

pub fn write_rotation_workspace(
    workspace_root: &Path,
    document: &RotationWorkspaceDocument,
) -> Result<()> {
    fs::create_dir_all(workspace_root)
        .with_context(|| format!("create {}", workspace_root.display()))?;
    fs::create_dir_all(workspace_root.join("packages"))
        .with_context(|| format!("create {}", workspace_root.join("packages").display()))?;
    write_json(&rotation_workspace_manifest_path(workspace_root), document)
}

pub fn inspect_rotation_workspace(
    workspace_root: &Path,
    document: &RotationWorkspaceDocument,
) -> RotationWorkspaceStatus {
    let mut validation_errors = Vec::new();
    let mut missing_secret_entries = Vec::new();
    let mut seen_members = HashSet::new();
    let mut local_target_member_index = None;
    let mut local_replace_profile_id = None;
    let mut local_target_count = 0usize;
    let mut remote_target_count = 0usize;

    if document.version != 1 {
        validation_errors.push(format!(
            "unsupported rotation workspace version {}; expected 1",
            document.version
        ));
    }
    if document.next_threshold == 0 || document.next_threshold > document.next_count {
        validation_errors.push("rotation threshold/count is invalid".to_string());
    }
    if document.targets.len() != document.next_count as usize {
        validation_errors.push(format!(
            "rotation workspace must contain exactly {} target entries",
            document.next_count
        ));
    }
    for source in &document.source_packages {
        if source.package_secret_env.is_none() && source.package_secret_file.is_none() {
            missing_secret_entries.push(source.package_path.clone());
        }
    }
    for target in &document.targets {
        if !seen_members.insert(target.member_index) {
            validation_errors.push(format!(
                "member {} is assigned more than once",
                target.member_index
            ));
        }
        if target.member_index == 0 || target.member_index > document.next_count {
            validation_errors.push(format!(
                "member {} is outside the configured rotated count {}",
                target.member_index, document.next_count
            ));
        }
        if target.label.trim().is_empty() {
            validation_errors.push(format!(
                "member {} is missing a label",
                target.member_index
            ));
        }
        if target.relays.is_empty() {
            validation_errors.push(format!(
                "member {} must have at least one relay",
                target.member_index
            ));
        }
        match target.mode {
            RotationTargetMode::LocalReplace => {
                local_target_count += 1;
                local_target_member_index = Some(target.member_index);
                local_replace_profile_id = target.replace_profile_id.clone();
                if target.replace_profile_id.as_deref().unwrap_or("").trim().is_empty() {
                    validation_errors.push(format!(
                        "member {} must declare replace_profile_id for local_replace",
                        target.member_index
                    ));
                }
                if target.usage_hint.is_some() {
                    validation_errors.push(format!(
                        "member {} must not set usage_hint for local_replace",
                        target.member_index
                    ));
                }
            }
            RotationTargetMode::Bfonboard => {
                remote_target_count += 1;
                if target.usage_hint.is_none() {
                    validation_errors.push(format!(
                        "member {} must declare usage_hint for bfonboard output",
                        target.member_index
                    ));
                }
            }
        }
    }
    if local_target_count != 1 {
        validation_errors.push("rotation workspace must contain exactly one local_replace target".to_string());
    }

    RotationWorkspaceStatus {
        workspace_path: workspace_root.display().to_string(),
        ready: validation_errors.is_empty()
            && missing_secret_entries.is_empty()
            && document.source_packages.len() >= document.source_threshold as usize,
        source_profile_id: document.source_profile_id.clone(),
        source_group_id: document.source_group_id.clone(),
        source_group_public_key: document.source_group_public_key.clone(),
        source_threshold: document.source_threshold,
        next_threshold: document.next_threshold,
        next_count: document.next_count,
        source_packages_present: document.source_packages.len(),
        source_packages_required: document.source_threshold as usize,
        local_target_member_index,
        local_replace_profile_id,
        remote_target_count,
        missing_secret_entries,
        validation_errors,
    }
}

pub async fn generate_rotation_workspace(
    paths: &ShellPaths,
    workspace_root: &Path,
    source_passwords: Vec<String>,
    vault_passphrase: Option<String>,
    distribution_password: Option<String>,
) -> Result<RotationGenerateResult> {
    let document = load_rotation_workspace(workspace_root)?;
    let status = inspect_rotation_workspace(workspace_root, &document);
    if !status.validation_errors.is_empty() {
        bail!(
            "rotation workspace is invalid: {}",
            status.validation_errors.join("; ")
        );
    }
    if document.source_packages.len() < document.source_threshold as usize {
        bail!(
            "rotation requires at least {} source packages",
            document.source_threshold
        );
    }
    if source_passwords.len() != document.source_packages.len() {
        bail!(
            "rotation source password count {} does not match source package count {}",
            source_passwords.len(),
            document.source_packages.len()
        );
    }

    let mut recovered = Vec::new();
    for (index, source) in document.source_packages.iter().enumerate() {
        let package_raw = fs::read_to_string(&source.package_path)
            .with_context(|| format!("read {}", source.package_path))?;
        let (_, payload) = preview_bfshare_recovery(&package_raw, source_passwords[index].clone(), None)
            .await
            .with_context(|| format!("recover {}", source.package_path))?;
        recovered.push(payload);
    }
    let current_group = group_from_payload(&recovered[0])?;
    let current_group_id = hex::encode(get_group_id(&current_group).context("derive current group id")?);
    let current_group_pk = hex::encode(current_group.group_pk);
    if current_group_id != document.source_group_id {
        bail!("rotation sources do not match the workspace source group id");
    }
    if current_group_pk != document.source_group_public_key {
        bail!("rotation sources do not match the workspace group public key");
    }
    for payload in recovered.iter().skip(1) {
        let candidate = group_from_payload(payload)?;
        if hex::encode(candidate.group_pk) != current_group_pk {
            bail!("rotation sources do not share the same group public key");
        }
        if hex::encode(get_group_id(&candidate)?) != current_group_id {
            bail!("rotation sources do not belong to the same current group configuration");
        }
    }

    let shares = recovered
        .iter()
        .map(|payload| share_from_payload(&current_group, payload))
        .collect::<Result<Vec<_>>>()?;

    let rotated = rotate_keyset_dealer(
        &current_group,
        RotateKeysetRequest {
            shares,
            threshold: document.next_threshold,
            count: document.next_count,
        },
    )
    .map_err(|error| anyhow!("rotate keyset: {error}"))?;

    let local_target = document
        .targets
        .iter()
        .find(|target| target.mode == RotationTargetMode::LocalReplace)
        .ok_or_else(|| anyhow!("rotation workspace is missing a local_replace target"))?;
    let local_share = rotated
        .next
        .shares
        .iter()
        .find(|share| share.idx == local_target.member_index)
        .ok_or_else(|| anyhow!("rotated share {} not found", local_target.member_index))?;
    let replace_profile_id = local_target
        .replace_profile_id
        .clone()
        .ok_or_else(|| anyhow!("local_replace target is missing replace_profile_id"))?;
    let target = read_profile(paths, &replace_profile_id)?;
    let target_payload = profile_to_package_payload(paths, &replace_profile_id, vault_passphrase.clone())?;
    let local_payload = rotation_payload_from_share(
        &document.source_keyset_name,
        &rotated.next.group,
        local_share,
        local_target.label.clone(),
        local_target.relays.clone(),
    )?;
    let import = finalize_rotation_update_import(
        paths,
        &target,
        target_payload,
        &rotated.next.group,
        local_payload,
        vault_passphrase.clone(),
    )?;
    let profile = match import {
        ProfileImportResult::ProfileCreated { profile, .. } => profile,
        _ => bail!("rotation did not produce a local profile"),
    };
    publish_profile_backup(paths, &profile.id, vault_passphrase.clone()).await?;

    let remote_targets = document
        .targets
        .iter()
        .filter(|target| target.mode == RotationTargetMode::Bfonboard)
        .collect::<Vec<_>>();
    let distribution_password = if remote_targets.is_empty() {
        None
    } else {
        Some(distribution_password.ok_or_else(|| anyhow!("rotation requires a distribution secret to emit bfonboard packages"))?)
    };

    let packages_dir = workspace_root.join("packages");
    fs::create_dir_all(&packages_dir)
        .with_context(|| format!("create {}", packages_dir.display()))?;
    let mut generated_packages = Vec::new();
    for target in remote_targets {
        let share = rotated
            .next
            .shares
            .iter()
            .find(|share| share.idx == target.member_index)
            .ok_or_else(|| anyhow!("rotated share {} not found", target.member_index))?;
        let payload = rotation_payload_from_share(
            &document.source_keyset_name,
            &rotated.next.group,
            share,
            target.label.clone(),
            target.relays.clone(),
        )?;
        publish_profile_payload_backup(&payload).await?;
        let output_path = target
            .output_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| packages_dir.join(format!("member-{}.bfonboard.txt", target.member_index)));
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let package = export_rotated_onboarding_package(
            &rotated.next.group,
            local_share,
            share,
            target.relays.clone(),
            distribution_password
                .as_ref()
                .expect("distribution password should exist when remote targets exist")
                .clone(),
        )?;
        write_package_output(Some(&output_path), &package)?;
        generated_packages.push(RotationGeneratedPackage {
            member_index: target.member_index,
            label: target.label.clone(),
            profile_id: payload.profile_id,
            usage_hint: target
                .usage_hint
                .ok_or_else(|| anyhow!("rotation target {} is missing usage_hint", target.member_index))?,
            path: output_path.display().to_string(),
        });
    }

    Ok(RotationGenerateResult {
        workspace_path: workspace_root.display().to_string(),
        source_group_id: document.source_group_id,
        next_group_id: hex::encode(rotated.next_group_id),
        replaced_profile_id: replace_profile_id,
        profile,
        generated_packages,
    })
}

pub(crate) fn import_profile_from_bfprofile_payload(
    paths: &ShellPaths,
    payload: BfProfilePayload,
    label: Option<String>,
    relay_profile: Option<String>,
    vault_passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    paths.ensure()?;
    let relay_profile_id = ensure_onboarding_relay_profile(
        paths,
        relay_profile,
        Some(label.as_deref().unwrap_or(&payload.device.name)),
        &payload.device.relays,
    )?;
    let group = group_from_payload(&payload)?;
    let share = bifrost_core::types::SharePackage {
        idx: find_member_index_for_share_secret(&group, &payload.device.share_secret)?,
        seckey: hex_to_bytes32(&payload.device.share_secret)?,
    };
    let now = now_unix_secs();
    let group_ref = store_group_package(paths, &group)?;
    let share_raw = serde_json::to_string_pretty(&SharePackageWire::from(share.clone()))
        .context("serialize bfprofile share package")?;
    let vault_record = store_secret_payload(
        paths,
        "share_package",
        "bfprofile_import",
        &share_raw,
        vault_passphrase,
    )?;
    let mut profile = build_profile_manifest(
        paths,
        &payload.profile_id,
        label.unwrap_or(payload.device.name),
        group_ref,
        vault_record.id.clone(),
        relay_profile_id,
        now,
    );
    profile.policy_overrides =
        build_policy_overrides_value(&payload.device.manual_peer_policy_overrides)?;
    profile.remote_policy_observations =
        build_remote_policy_observations_value(&payload.device.remote_peer_policy_observations)?;
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

pub fn create_generated_keyset_draft(
    keyset_name: String,
    threshold: u16,
    count: u16,
) -> Result<GeneratedKeysetDraft> {
    let bundle = create_keyset(CreateKeysetConfig { threshold, count })
        .map_err(|error| anyhow!("create keyset: {error}"))?;
    let shares = bundle
        .shares
        .iter()
        .map(|share| {
            Ok(GeneratedShareDraft {
                member_idx: share.idx,
                label: format!("{keyset_name} Device {}", share.idx),
                share_public_key: derive_member_pubkey_hex(share.seckey)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(GeneratedKeysetDraft {
        keyset_name,
        threshold,
        count,
        group_public_key: hex::encode(bundle.group.group_pk),
        shares,
        group: bundle.group,
        share_packages: bundle.shares,
    })
}

pub fn import_generated_share(
    paths: &ShellPaths,
    draft: &GeneratedKeysetDraft,
    member_idx: u16,
    label: String,
    relay_urls: Vec<String>,
    vault_passphrase: Option<String>,
) -> Result<ProfileImportResult> {
    if relay_urls.is_empty() {
        bail!("at least one relay is required");
    }
    let Some(share) = draft
        .share_packages
        .iter()
        .find(|share| share.idx == member_idx)
    else {
        bail!("generated share {member_idx} not found");
    };
    let local_pubkey = derive_member_pubkey_hex(share.seckey)?;
    let share_secret_hex = hex::encode(share.seckey);
    let payload = BfProfilePayload {
        profile_id: derive_profile_id_for_share_secret(&share_secret_hex)?,
        version: 1,
        keyset_name: draft.keyset_name.clone(),
        device: BfProfileDevice {
            name: label.clone(),
            share_secret: share_secret_hex,
            manual_peer_policy_overrides: draft
                .group
                .members
                .iter()
                .map(|member| hex::encode(&member.pubkey[1..]))
                .filter(|pubkey| pubkey != &local_pubkey)
                .map(|pubkey| BfManualPeerPolicyOverride {
                    pubkey,
                    policy: core_peer_policy_override_to_bf(&PeerPolicyOverride::from_peer_policy(
                        &PeerPolicy::default(),
                    )),
                })
                .collect(),
            remote_peer_policy_observations: Vec::new(),
            relays: relay_urls,
        },
        group_package: GroupPackageWire::from(draft.group.clone()),
    };
    import_profile_from_bfprofile_payload(paths, payload, Some(label), None, vault_passphrase)
}

pub fn export_generated_onboarding_package(
    draft: &GeneratedKeysetDraft,
    member_idx: u16,
    relays: Vec<String>,
    peer_pubkey: String,
    package_password: String,
) -> Result<String> {
    if relays.is_empty() {
        bail!("at least one relay is required");
    }
    let Some(share) = draft
        .share_packages
        .iter()
        .find(|share| share.idx == member_idx)
    else {
        bail!("generated share {member_idx} not found");
    };
    encode_bfonboard_package(
        &BfOnboardPayload {
            share_secret: hex::encode(share.seckey),
            relays,
            peer_pk: peer_pubkey,
        },
        &package_password,
    )
    .context("encode bfonboard package")
}

fn export_rotated_onboarding_package(
    group: &bifrost_core::types::GroupPackage,
    local_share: &bifrost_core::types::SharePackage,
    target_share: &bifrost_core::types::SharePackage,
    relays: Vec<String>,
    package_password: String,
) -> Result<String> {
    if relays.is_empty() {
        bail!("at least one relay is required");
    }
    if local_share.idx == target_share.idx {
        bail!("rotation onboarding target must differ from the local replacement member");
    }
    if !group.members.iter().any(|member| member.idx == local_share.idx) {
        bail!("rotated group is missing the local replacement member");
    }
    if !group.members.iter().any(|member| member.idx == target_share.idx) {
        bail!("rotated group is missing the target member");
    }
    encode_bfonboard_package(
        &BfOnboardPayload {
            share_secret: hex::encode(target_share.seckey),
            relays,
            peer_pk: derive_member_pubkey_hex(local_share.seckey)?,
        },
        &package_password,
    )
    .context("encode rotated bfonboard package")
}

fn profile_to_package_payload(
    paths: &ShellPaths,
    profile_id: &str,
    vault_passphrase: Option<String>,
) -> Result<BfProfilePayload> {
    let profile = read_profile(paths, profile_id)?;
    let (manifest, resolved) =
        resolve_profile_runtime_with_passphrase(paths, profile_id, vault_passphrase)?;
    let manual_peer_policy_overrides = resolved
        .manual_policy_overrides
        .iter()
        .map(|(pubkey, policy_override)| BfManualPeerPolicyOverride {
            pubkey: pubkey.clone(),
            policy: core_peer_policy_override_to_bf(policy_override),
        })
        .collect::<Vec<_>>();
    Ok(BfProfilePayload {
        profile_id: profile.id.clone(),
        version: 1,
        keyset_name: profile.label,
        device: BfProfileDevice {
            name: manifest.label,
            share_secret: hex::encode(resolved.share.seckey),
            manual_peer_policy_overrides,
            remote_peer_policy_observations: Vec::new(),
            relays: resolved.relays,
        },
        group_package: GroupPackageWire::from(resolved.group),
    })
}

fn group_from_payload(payload: &BfProfilePayload) -> Result<bifrost_core::types::GroupPackage> {
    payload
        .group_package
        .clone()
        .try_into()
        .map_err(|e: bifrost_codec::CodecError| anyhow!("invalid group package: {e}"))
}

fn share_from_payload(
    group: &bifrost_core::types::GroupPackage,
    payload: &BfProfilePayload,
) -> Result<bifrost_core::types::SharePackage> {
    let share_secret = hex::decode(&payload.device.share_secret)?;
    let seckey: [u8; 32] = share_secret
        .try_into()
        .map_err(|_| anyhow!("invalid share secret"))?;
    let share_public_key = hex::encode(
        k256::SecretKey::from_slice(&seckey)
            .map_err(|error| anyhow!("invalid share secret: {error}"))?
            .public_key()
            .to_sec1_bytes(),
    );
    let xonly = share_public_key
        .strip_prefix("02")
        .or_else(|| share_public_key.strip_prefix("03"))
        .unwrap_or(&share_public_key)
        .to_string();
    let member = group
        .members
        .iter()
        .find(|member| hex::encode(&member.pubkey[1..]) == xonly)
        .ok_or_else(|| anyhow!("share secret does not match any member in the recovered group"))?;
    Ok(bifrost_core::types::SharePackage {
        idx: member.idx,
        seckey,
    })
}

fn rotation_payload_from_share(
    keyset_name: &str,
    group: &bifrost_core::types::GroupPackage,
    share: &bifrost_core::types::SharePackage,
    label: String,
    relays: Vec<String>,
) -> Result<BfProfilePayload> {
    let share_secret = hex::encode(share.seckey);
    let local_pubkey = derive_member_pubkey_hex(share.seckey)?;
    Ok(BfProfilePayload {
        profile_id: derive_profile_id_for_share_secret(&share_secret)?,
        version: 1,
        keyset_name: keyset_name.to_string(),
        device: BfProfileDevice {
            name: label,
            share_secret,
            manual_peer_policy_overrides: group
                .members
                .iter()
                .map(|member| hex::encode(&member.pubkey[1..]))
                .filter(|pubkey| pubkey != &local_pubkey)
                .map(|pubkey| BfManualPeerPolicyOverride {
                    pubkey,
                    policy: core_peer_policy_override_to_bf(&PeerPolicyOverride::from_peer_policy(
                        &PeerPolicy::default(),
                    )),
                })
                .collect(),
            remote_peer_policy_observations: Vec::new(),
            relays,
        },
        group_package: GroupPackageWire::from(group.clone()),
    })
}

async fn publish_profile_payload_backup(payload: &BfProfilePayload) -> Result<()> {
    let backup = create_encrypted_profile_backup(payload).context("build encrypted backup")?;
    let event = build_profile_backup_event(&payload.device.share_secret, &backup, None)
        .context("build backup event")?;
    publish_nostr_event(&payload.device.relays, &event).await
}

fn preview_from_profile_payload(
    payload: &BfProfilePayload,
    label: Option<String>,
    source: &'static str,
) -> Result<ProfilePreview> {
    let share_public_key = derive_member_pubkey_hex(hex_to_bytes32(&payload.device.share_secret)?)?;
    Ok(ProfilePreview {
        profile_id: payload.profile_id.clone(),
        label: label.unwrap_or_else(|| payload.device.name.clone()),
        share_public_key,
        group_public_key: payload.group_package.group_pk.clone(),
        threshold: payload.group_package.threshold as usize,
        total_count: payload.group_package.members.len(),
        relays: payload.device.relays.clone(),
        peer_pubkey: None,
        source,
    })
}

fn preview_from_bootstrap_completion(
    completion: &BootstrapImportResult,
    label: Option<String>,
    source: &'static str,
    peer_pubkey: Option<String>,
) -> Result<ProfilePreview> {
    let share_public_key = derive_member_pubkey_hex(completion.share.seckey)?;
    Ok(ProfilePreview {
        profile_id: derive_profile_id_for_share_secret(&hex::encode(completion.share.seckey))?,
        label: label.unwrap_or_else(|| format!("Onboarded Device {}", completion.share.idx)),
        share_public_key,
        group_public_key: hex::encode(completion.group.group_pk),
        threshold: completion.group.threshold as usize,
        total_count: completion.group.members.len(),
        relays: completion.relays.clone(),
        peer_pubkey,
        source,
    })
}

fn build_policy_overrides_value(policies: &[BfManualPeerPolicyOverride]) -> Result<Value> {
    serde_json::to_value(PolicyOverridesDocument {
        default_override: None,
        peer_overrides: policies
            .iter()
            .map(|policy| PolicyOverrideEntry {
                pubkey: policy.pubkey.clone(),
                policy_override: PeerPolicyOverride {
                    request: bifrost_core::types::MethodPolicyOverride {
                        echo: match policy.policy.request.echo {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        ping: match policy.policy.request.ping {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        onboard: match policy.policy.request.onboard {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        sign: match policy.policy.request.sign {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        ecdh: match policy.policy.request.ecdh {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                    },
                    respond: bifrost_core::types::MethodPolicyOverride {
                        echo: match policy.policy.respond.echo {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        ping: match policy.policy.respond.ping {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        onboard: match policy.policy.respond.onboard {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        sign: match policy.policy.respond.sign {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                        ecdh: match policy.policy.respond.ecdh {
                            frostr_utils::BfPolicyOverrideValue::Unset => {
                                PolicyOverrideValue::Unset
                            }
                            frostr_utils::BfPolicyOverrideValue::Allow => {
                                PolicyOverrideValue::Allow
                            }
                            frostr_utils::BfPolicyOverrideValue::Deny => PolicyOverrideValue::Deny,
                        },
                    },
                },
            })
            .collect(),
    })
    .context("serialize policy overrides")
}

fn write_package_output(out_path: Option<&Path>, package: &str) -> Result<()> {
    if let Some(path) = out_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(path, package).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

fn rotation_workspace_manifest_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join("rotation.json")
}

fn hex_to_bytes32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("decode hex32 {value}"))?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex value");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn find_member_index_for_share_secret(
    group: &bifrost_core::types::GroupPackage,
    share_secret: &str,
) -> Result<u16> {
    let local_pubkey = derive_member_pubkey_hex(hex_to_bytes32(share_secret)?)?;
    group
        .members
        .iter()
        .find(|member| hex::encode(&member.pubkey[1..]) == local_pubkey)
        .map(|member| member.idx)
        .ok_or_else(|| anyhow!("share secret does not match any group member"))
}

fn resolve_profile_runtime_with_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    vault_passphrase: Option<String>,
) -> Result<(ProfileManifest, ResolvedAppConfig)> {
    let profile = read_profile(paths, profile_id)?;
    let relay_profile = read_relay_profile(paths, &profile.relay_profile)?;
    let group_raw = fs::read_to_string(&profile.group_ref)
        .with_context(|| format!("read {}", profile.group_ref))?;
    let share_raw = load_share_payload_with_passphrase(paths, &profile, vault_passphrase)?;
    let group = parse_group_package(&group_raw).context("parse profile group package")?;
    let share = parse_share_package(&share_raw).context("parse profile share package")?;
    let (peers, manual_policy_overrides) =
        resolve_profile_peers_and_overrides(&group, &share, profile.policy_overrides.clone())
            .context("resolve peer policy overrides")?;
    let remote_policy_observations =
        parse_remote_policy_observations_doc(profile.remote_policy_observations.clone())
            .context("resolve remote policy observations")?;
    let options: AppOptions = if profile.runtime_options.is_null() {
        AppOptions::default()
    } else {
        serde_json::from_value(profile.runtime_options.clone()).context("parse runtime options")?
    };
    Ok((
        profile.clone(),
        ResolvedAppConfig {
            group,
            share,
            state_path: PathBuf::from(&profile.state_path),
            relays: relay_profile.relays,
            peers,
            manual_policy_overrides,
            remote_policy_observations,
            options,
        },
    ))
}

async fn publish_nostr_event(relays: &[String], event: &Event) -> Result<()> {
    let event_value = serde_json::to_value(event).context("serialize nostr event")?;
    let payload = serde_json::json!(["EVENT", event_value]).to_string();
    let mut published = false;
    for relay in relays {
        let attempt = async {
            let (mut stream, _) =
                timeout(TokioDuration::from_secs(3), connect_async(relay.as_str()))
                    .await
                    .map_err(|_| anyhow!("timed out connecting to relay"))??;
            stream.send(Message::Text(payload.clone().into())).await?;
            while let Some(message) = timeout(TokioDuration::from_secs(3), stream.next())
                .await
                .map_err(|_| anyhow!("timed out waiting for relay acknowledgement"))?
            {
                let message = message?;
                if let Message::Text(text) = message {
                    let value: Value =
                        serde_json::from_str(&text).context("parse relay response")?;
                    if let Some(array) = value.as_array() {
                        match array.first().and_then(Value::as_str) {
                            Some("OK") => {
                                let ok = array.get(2).and_then(Value::as_bool).unwrap_or(false);
                                if !ok {
                                    bail!("relay rejected backup event");
                                }
                                return Ok(());
                            }
                            Some("NOTICE") => bail!(
                                "{}",
                                array
                                    .get(1)
                                    .and_then(Value::as_str)
                                    .unwrap_or("relay notice")
                            ),
                            _ => {}
                        }
                    }
                }
            }
            bail!("relay closed before confirming backup event")
        }
        .await;
        if attempt.is_ok() {
            published = true;
            break;
        }
    }
    if !published {
        bail!("failed to publish encrypted profile backup to configured relays");
    }
    Ok(())
}

async fn probe_relays(relays: &[String]) -> Vec<RelayProbeResult> {
    let mut results = Vec::with_capacity(relays.len());
    for relay in relays {
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
        results.push(outcome);
    }
    results
}

async fn fetch_latest_nostr_event(
    relays: &[String],
    author_pubkey: &str,
    kind: u16,
) -> Result<Event> {
    let subscription_id = format!("igloo-shell-{}", now_unix_secs());
    let filter = serde_json::json!({
        "authors": [author_pubkey],
        "kinds": [kind],
    });
    let request = serde_json::json!(["REQ", subscription_id, filter]).to_string();
    let close = serde_json::json!(["CLOSE", subscription_id]).to_string();
    let mut best: Option<Event> = None;
    for relay in relays {
        let attempt = async {
            let (mut stream, _) = connect_async(relay.as_str()).await?;
            stream.send(Message::Text(request.clone().into())).await?;
            while let Some(message) =
                tokio::time::timeout(Duration::from_secs(3), stream.next()).await?
            {
                let message = message?;
                if let Message::Text(text) = message {
                    let value: Value = serde_json::from_str(&text).context("parse relay event")?;
                    let Some(array) = value.as_array() else {
                        continue;
                    };
                    match array.first().and_then(Value::as_str) {
                        Some("EVENT") => {
                            if let Some(event_value) = array.get(2) {
                                let event: Event = serde_json::from_value(event_value.clone())
                                    .context("decode nostr event")?;
                                if best
                                    .as_ref()
                                    .map(|existing| event.created_at > existing.created_at)
                                    .unwrap_or(true)
                                {
                                    best = Some(event);
                                }
                            }
                        }
                        Some("EOSE") => break,
                        Some("NOTICE") => break,
                        _ => {}
                    }
                }
            }
            let _ = stream.send(Message::Text(close.clone().into())).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let _ = attempt;
    }
    best.ok_or_else(|| anyhow!("no encrypted profile backup was found for this share"))
}

pub async fn run_setup(
    paths: &ShellPaths,
    request: SetupRequest,
    start_daemon: bool,
) -> Result<SetupResult> {
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
        _ => bail!(
            "setup requires both --group and --share; use `igloo-shell onboard` for onboarding packages"
        ),
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
    profile
        .relays
        .retain(|relay| !relays.iter().any(|value| value == relay));
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

fn store_group_package(
    paths: &ShellPaths,
    group: &bifrost_core::types::GroupPackage,
) -> Result<String> {
    let group_id = get_group_id(group).context("derive group id")?;
    let path = paths
        .groups_dir
        .join(format!("{}.json", hex::encode(group_id)));
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
            "default_override": null,
            "peer_overrides": []
        }),
        remote_policy_observations: Value::Array(Vec::new()),
        state_path: state_dir.join("signer-state.bin").display().to_string(),
        daemon_socket_path: state_dir.join("daemon.sock").display().to_string(),
        created_at,
        last_used_at: Some(created_at),
    }
}

fn parse_policy_overrides_doc(value: Value) -> Result<PolicyOverridesDocument> {
    if value.is_null() {
        return Ok(PolicyOverridesDocument {
            default_override: None,
            peer_overrides: Vec::new(),
        });
    }
    serde_json::from_value(value).context("parse policy overrides document")
}

fn parse_remote_policy_observations_doc(
    value: Value,
) -> Result<HashMap<String, bifrost_core::types::PeerScopedPolicyProfile>> {
    if value.is_null() {
        return Ok(HashMap::new());
    }
    let observations: Vec<BfRemotePeerPolicyObservation> =
        serde_json::from_value(value).context("parse remote policy observations")?;
    let mut remote_policy_observations = HashMap::new();
    for observation in observations {
        remote_policy_observations.insert(
            observation.pubkey.clone(),
            bf_peer_scoped_policy_profile_to_core(&observation.profile).with_context(|| {
                format!("parse remote policy observation {}", observation.pubkey)
            })?,
        );
    }
    Ok(remote_policy_observations)
}

fn build_remote_policy_observations_value(
    observations: &[BfRemotePeerPolicyObservation],
) -> Result<Value> {
    serde_json::to_value(observations).context("serialize remote policy observations")
}

fn resolve_profile_peers_and_overrides(
    group: &bifrost_core::types::GroupPackage,
    share: &bifrost_core::types::SharePackage,
    value: Value,
) -> Result<(Vec<String>, HashMap<String, PeerPolicyOverride>)> {
    let document = parse_policy_overrides_doc(value)?;
    let local_pubkey = derive_member_pubkey_hex(share.seckey)?;
    let peer_keys = group
        .members
        .iter()
        .map(|member| hex::encode(&member.pubkey[1..]))
        .filter(|pubkey| pubkey != &local_pubkey)
        .collect::<Vec<_>>();

    let mut peers = Vec::with_capacity(peer_keys.len());
    let mut manual_policy_overrides = HashMap::new();
    for pubkey in peer_keys {
        let effective_override = effective_policy_override(&document, &pubkey);
        manual_policy_overrides.insert(pubkey.clone(), effective_override);
        peers.push(pubkey);
    }
    peers.sort();
    Ok((peers, manual_policy_overrides))
}

fn derive_member_pubkey_hex(seckey: [u8; 32]) -> Result<String> {
    let secret = k256::SecretKey::from_slice(&seckey).context("invalid share seckey")?;
    let point = secret.public_key().to_encoded_point(true);
    Ok(hex::encode(&point.as_bytes()[1..]))
}

fn derive_profile_id_for_share_secret(share_secret_hex: &str) -> Result<String> {
    derive_profile_id_from_share_secret(share_secret_hex).context("derive profile id")
}

fn ensure_profile_id_unused(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    if paths.profile_path(profile_id).exists() {
        bail!("profile {} already exists", profile_id);
    }
    Ok(())
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

fn validate_profile_unlock(
    paths: &ShellPaths,
    profile: &ProfileManifest,
    passphrase: Option<String>,
) -> Result<()> {
    let _ = load_share_payload_with_passphrase(paths, profile, passphrase)?;
    Ok(())
}

pub fn validate_profile_unlock_with_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let profile = read_profile(paths, profile_id)?;
    validate_profile_unlock(paths, &profile, passphrase)
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

fn is_vault_ref_in_use(
    paths: &ShellPaths,
    exclude_profile_id: &str,
    vault_id: &str,
) -> Result<bool> {
    Ok(list_profiles(paths)?
        .into_iter()
        .any(|profile| profile.id != exclude_profile_id && profile.share_ref == vault_id))
}

fn remove_vault_record(paths: &ShellPaths, vault_id: &str) -> Result<()> {
    let record = read_vault_record(paths, vault_id)?;
    let metadata_path = paths.vault_metadata_path(vault_id);
    if metadata_path.exists() {
        fs::remove_file(&metadata_path)
            .with_context(|| format!("remove {}", metadata_path.display()))?;
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
    let profile_id = derive_profile_id_for_share_secret(&hex::encode(completion.share.seckey))?;
    ensure_profile_id_unused(paths, &profile_id)?;
    let group_ref = store_group_package(paths, &completion.group)?;
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
    let diagnostics =
        match persist_validated_onboarding_state(Path::new(&profile.state_path), &completion) {
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
        bail!(
            "relay profile {} must contain at least one relay",
            profile.id
        );
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
    use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
    use bifrost_core::types::{GroupPackage, MemberPackage, SharePackage};
    use bifrost_signer::{DeviceState, DeviceStore};
    use frostr_utils::{
        BfOnboardPayload, CreateKeysetConfig, create_keyset, encode_bfonboard_package,
    };
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
            rotations_dir: root.join("state").join("igloo-shell").join("rotations"),
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

        let (updated, effective_override) = set_profile_peer_policy_override(
            &paths,
            "alice",
            "deadbeef",
            PolicyDirection::Request,
            PolicyMethod::Sign,
            PolicyOverrideValue::Deny,
        )
        .expect("persist peer policy");
        let document =
            parse_policy_overrides_doc(updated.policy_overrides).expect("parse policy overrides");
        assert_eq!(document.peer_overrides.len(), 1);
        assert_eq!(document.peer_overrides[0].pubkey, "deadbeef");
        assert_eq!(
            document.peer_overrides[0].policy_override.request.sign,
            PolicyOverrideValue::Deny
        );
        assert_eq!(effective_override.request.sign, PolicyOverrideValue::Deny);

        let (cleared, effective_policy) =
            clear_profile_peer_policy(&paths, "alice", "deadbeef").expect("clear peer policy");
        let cleared_doc =
            parse_policy_overrides_doc(cleared.policy_overrides).expect("parse cleared overrides");
        assert!(cleared_doc.peer_overrides.is_empty());
        assert_eq!(effective_policy, PeerPolicyOverride::default());
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
        let package = BfOnboardPayload {
            share_secret: hex::encode(share.seckey),
            peer_pk: hex::encode(&inviter.pubkey[1..]),
            relays: vec!["ws://127.0.0.1:8194".to_string()],
        };
        let encoded = encode_bfonboard_package(&package, "test-password").expect("encode");
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
                    group_member_count: group.members.len(),
                    bootstrap_nonces: vec![onboarding_nonce.clone()],
                    bootstrap_state: bifrost_app::onboarding::BootstrapStateSnapshot {
                        device_state_hex: hex::encode(
                            bincode::serialize(&onboarding_state)
                                .expect("serialize bootstrap state"),
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
        let share_raw =
            load_share_payload_with_passphrase(&paths, &profile, Some("vault-pass".to_string()))
                .expect("decrypt share payload");
        let parsed_share = parse_share_package(&share_raw).expect("parse stored share");
        assert_eq!(parsed_share.idx, share.idx);
        assert!(read_vault_record(&paths, &vault_record.id).is_ok());
        let store = bifrost_app::runtime::EncryptedFileStore::new(
            PathBuf::from(&profile.state_path),
            share.clone(),
        );
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

    #[test]
    fn bfprofile_export_and_import_round_trip() {
        let paths = test_paths("bfprofile-roundtrip");
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
        let group_path = paths.data_dir.join("group.json");
        let share_path = paths.data_dir.join("share.json");
        write_json(&group_path, &GroupPackageWire::from(bundle.group.clone()))
            .expect("write group");
        write_json(
            &share_path,
            &SharePackageWire::from(bundle.shares[0].clone()),
        )
        .expect("write share");

        let import = import_profile_from_files(
            &paths,
            &group_path,
            &share_path,
            Some("Alice".to_string()),
            Some("local".to_string()),
            Some("vault-pass".to_string()),
        )
        .expect("import raw profile");
        let ProfileImportResult::ProfileCreated { profile, .. } = import else {
            panic!("expected profile created");
        };

        let exported = export_profile_as_bfprofile(
            &paths,
            &profile.id,
            "package-pass".to_string(),
            Some("vault-pass".to_string()),
            None,
        )
        .expect("export bfprofile");
        let imported = import_profile_from_bfprofile_value(
            &paths,
            &exported.package,
            "package-pass".to_string(),
            Some("Recovered".to_string()),
            Some("local".to_string()),
            Some("vault-pass".to_string()),
        )
        .expect("import bfprofile");

        let ProfileImportResult::ProfileCreated { profile, .. } = imported else {
            panic!("expected imported profile created");
        };
        assert_eq!(profile.label, "Recovered");
        let report = doctor_profile(&paths, &profile).expect("doctor profile");
        assert!(report.group_present);
        assert!(report.share_managed);
        validate_profile_unlock_with_passphrase(
            &paths,
            &profile.id,
            Some("vault-pass".to_string()),
        )
        .expect("unlock imported bfprofile");
    }
}
