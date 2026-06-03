use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use bifrost_app::onboarding::{
    BootstrapImportResult, complete_onboarding_package, persist_validated_onboarding_state,
};
use bifrost_codec::{
    parse_group_package, parse_share_package, wire::GroupPackageWire, wire::SharePackageWire,
};
use bifrost_core::get_group_id;
use bifrost_core::types::{PeerPolicy, PeerPolicyOverride};
use frostr_utils::{
    BfManualPeerPolicyOverride, BfOnboardPayload, BfProfileDevice, BfProfilePayload,
    CreateKeysetConfig, RotateKeysetRequest, build_profile_backup_event,
    core_peer_policy_override_to_bf, create_encrypted_profile_backup, create_keyset,
    decode_bfonboard_package, encode_bfonboard_package, rotate_keyset_dealer,
};
use futures_util::{SinkExt, StreamExt};
use nostr::Event;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use tokio::time::{Duration as TokioDuration, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[cfg(test)]
use bifrost_core::types::PolicyOverrideValue;
#[cfg(test)]
use bifrost_profile::{
    export_profile_as_bfprofile, import_profile_from_bfprofile_value, import_profile_from_files,
};
use bifrost_app::native_runtime::DaemonMetadata;
use bifrost_profile::{ProfileImportResult, StagedOnboardingImport};

// Temporary shell-side convenience contract for scripts and tests.
// Keep this env shim stable until the broader explicit-input migration lands.
const PROFILE_PASSPHRASE_ENV: &str = "IGLOO_SHELL_PROFILE_PASSPHRASE";
const ONBOARDING_ENV_PASSPHRASE: &str = "IGLOO_SHELL_ONBOARDING_PASSWORD";

mod checks;
mod config;
mod daemon;
mod encrypted_profile;
mod io;
mod onboarding;
mod packages;
mod paths;
mod profiles;
mod relay;
mod rotation;
mod shared;

use bifrost_profile::{
    EncryptedProfileRecord, ProfileManifest, ProfilePreview,
};
pub(crate) use bifrost_profile::{PolicyOverrideEntry, PolicyOverridesDocument};
pub use checks::{
    RelayConnectivityReport, RelayProbeResult, ShellCheckKind, ShellCheckResult,
    check_profile_runtime, test_relay_connectivity,
};
pub use config::{
    FallbackUnlockMode, KeyringPreference, RelayProfile, ShellConfig, load_relay_profiles,
    load_shell_config, save_relay_profiles, save_shell_config,
};
pub use daemon::{
    build_daemon_transport, daemon_clear_peer_policy_overrides, daemon_client,
    daemon_ecdh, daemon_log_path, daemon_onboard, daemon_peer_status, daemon_ping,
    daemon_runtime_config, daemon_runtime_diagnostics, daemon_runtime_metadata,
    daemon_runtime_readiness, daemon_runtime_status, daemon_set_policy_override, daemon_sign,
    daemon_wipe_state, resolve_profile_runtime, resolve_profile_runtime_for_passphrase,
    start_profile_daemon, start_profile_daemon_with_passphrase, stop_profile_daemon,
    stop_profile_daemon_typed,
};
pub(crate) use encrypted_profile::{
    decrypt_encrypted_profile, load_share_payload, load_share_payload_with_passphrase,
    remove_encrypted_profile, resolve_secret, store_encrypted_profile, validate_profile_unlock,
};
pub use encrypted_profile::{
    read_encrypted_profile, validate_profile_unlock_with_passphrase, write_encrypted_profile,
};
pub use io::now_unix_secs;
pub(crate) use io::{read_json, write_json};
pub(crate) use onboarding::import_profile_from_bfprofile_payload;
pub use onboarding::{
    connect_onboarding_package_preview, finalize_connected_onboarding_import,
    import_profile_from_onboarding_package, import_profile_from_onboarding_value, run_setup,
    stage_onboarding_import,
};
pub(crate) use packages::{
    build_policy_overrides_value, find_member_index_for_share_secret, group_from_payload,
    hex_to_bytes32, preview_from_bootstrap_completion, profile_to_package_payload,
    publish_profile_payload_backup, rotation_payload_from_share, rotation_workspace_manifest_path,
    share_from_payload, write_package_output,
};
use paths::ShellPaths;
pub use profiles::{
    PolicyDirection, PolicyMethod, clear_profile_peer_policy, doctor_profile, list_profiles,
    read_daemon_metadata, read_profile, read_relay_profile, remove_daemon_metadata, remove_profile,
    set_profile_default_policy_override, set_profile_peer_policy_override, write_daemon_metadata,
    write_profile,
};
pub(crate) use profiles::{effective_policy_override, touch_last_used_profile};
pub use relay::{add_relays, remove_relays, replace_relay_profile, set_default_relay_profile};
pub(crate) use relay::{probe_relays, publish_nostr_event};
pub use rotation::{
    apply_rotation_update_from_bfonboard_value, create_generated_keyset_draft,
    create_rotation_workspace, default_rotation_workspace_path,
    export_generated_onboarding_package, finalize_rotation_update_import,
    generate_rotation_workspace, import_generated_share, inspect_rotation_workspace,
    load_rotation_workspace, write_rotation_workspace,
};
pub(crate) use shared::{
    build_profile_manifest, derive_member_pubkey_hex, derive_profile_id_for_share_secret,
    ensure_onboarding_relay_profile, parse_policy_overrides_doc,
    resolve_profile_peers_and_overrides, shorten_unix_socket_path, store_group_package,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDoctorReport {
    pub profile_id: String,
    pub ok: bool,
    pub missing_paths: Vec<String>,
    pub relay_profile_exists: bool,
    pub group_present: bool,
    pub share_managed: bool,
    pub encrypted_profile_exists: bool,
    pub vault_unlock_ok: bool,
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
    pub passphrase: Option<String>,
    pub onboarding_password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GeneratedShareDraft {
    pub member_idx: u16,
    pub label: String,
    pub share_public_key: String,
}

#[derive(Debug, Clone)]
pub struct GeneratedKeysetDraft {
    pub group_name: String,
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
    pub source_group_name: String,
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

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_app::host::{
        ControlCommand, ControlRequest, ControlResponse, EcdhPayload, OnboardPayload, PingPayload,
        RuntimeDiagnosticsSnapshot, RuntimeStatusPayload, ShutdownPayload, SignPayload,
        UpdatedPayload, WipedPayload,
    };
    use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
    use bifrost_core::types::{GroupPackage, MemberPackage, SharePackage};
    use bifrost_signer::{
        DeviceConfig, DeviceState, DeviceStatus, DeviceStore, PeerStatus, RuntimeMetadata,
        RuntimeReadiness, RuntimeStatusSummary,
    };
    use frostr_utils::{
        BfOnboardPayload, CreateKeysetConfig, create_keyset, encode_bfonboard_package,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(unix)]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UnixListener;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn test_paths(name: &str) -> ShellPaths {
        let root = std::env::temp_dir().join(format!(
            "igloo-shell-tests-{}-{}",
            name,
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        ShellPaths::from_roots(root.join("config"), root.join("data"), root.join("state"))
    }

    #[cfg(unix)]
    fn sample_runtime_status() -> RuntimeStatusSummary {
        RuntimeStatusSummary {
            status: DeviceStatus {
                device_id: "device-1".to_string(),
                pending_ops: 0,
                last_active: 1_700_000_000,
                known_peers: 1,
                request_seq: 7,
            },
            metadata: RuntimeMetadata {
                device_id: "device-1".to_string(),
                member_idx: 1,
                share_public_key: "share-pubkey".to_string(),
                group_public_key: "group-pubkey".to_string(),
                peers: vec!["peer-1".to_string()],
            },
            readiness: RuntimeReadiness {
                runtime_ready: true,
                restore_complete: true,
                sign_ready: true,
                ecdh_ready: true,
                threshold: 1,
                signing_peer_count: 1,
                ecdh_peer_count: 1,
                last_refresh_at: Some(1_700_000_001),
                degraded_reasons: Vec::new(),
            },
            peers: vec![PeerStatus {
                idx: 2,
                pubkey: "peer-1".to_string(),
                known: true,
                last_seen: Some(1_700_000_001),
                online: true,
                incoming_available: 2,
                outgoing_available: 2,
                outgoing_spent: 0,
                can_sign: true,
                should_send_nonces: false,
            }],
            peer_permission_states: Vec::new(),
            pending_operations: Vec::new(),
        }
    }

    #[cfg(unix)]
    fn write_test_daemon_metadata(
        paths: &ShellPaths,
        profile_id: &str,
        socket_path: &Path,
        token: &str,
    ) {
        write_daemon_metadata(
            paths,
            profile_id,
            &DaemonMetadata {
                profile_id: profile_id.to_string(),
                pid: 1,
                socket_path: socket_path.display().to_string(),
                token: token.to_string(),
                log_path: paths.daemon_log_path(profile_id).display().to_string(),
                started_at: now_unix_secs(),
            },
        )
        .expect("write daemon metadata");
    }

    #[cfg(unix)]
    async fn spawn_fake_daemon_once(
        socket_path: PathBuf,
        expected_token: String,
        expected_command: ControlCommand,
        response_result: Value,
    ) -> tokio::task::JoinHandle<()> {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent).expect("create socket dir");
        }
        if socket_path.exists() {
            let _ = fs::remove_file(&socket_path);
        }
        let listener = UnixListener::bind(&socket_path).expect("bind unix listener");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept control stream");
            let mut request_bytes = Vec::new();
            stream
                .read_to_end(&mut request_bytes)
                .await
                .expect("read request");
            let request: ControlRequest =
                serde_json::from_slice(&request_bytes).expect("parse control request");
            assert_eq!(request.token, expected_token);
            match (request.command, expected_command) {
                (ControlCommand::RuntimeStatus, ControlCommand::RuntimeStatus)
                | (ControlCommand::RuntimeDiagnostics, ControlCommand::RuntimeDiagnostics)
                | (ControlCommand::RuntimeMetadata, ControlCommand::RuntimeMetadata)
                | (ControlCommand::Readiness, ControlCommand::Readiness)
                | (ControlCommand::PeerStatus, ControlCommand::PeerStatus)
                | (ControlCommand::ReadConfig, ControlCommand::ReadConfig)
                | (ControlCommand::Shutdown, ControlCommand::Shutdown)
                | (ControlCommand::Sign { .. }, ControlCommand::Sign { .. })
                | (ControlCommand::Ecdh { .. }, ControlCommand::Ecdh { .. })
                | (ControlCommand::Ping { .. }, ControlCommand::Ping { .. })
                | (ControlCommand::Onboard { .. }, ControlCommand::Onboard { .. })
                | (ControlCommand::WipeState, ControlCommand::WipeState)
                | (
                    ControlCommand::SetPolicyOverride { .. },
                    ControlCommand::SetPolicyOverride { .. },
                ) => {}
                (actual, expected) => {
                    panic!("unexpected command {actual:?}, expected {expected:?}")
                }
            }
            let response = ControlResponse {
                request_id: request.request_id,
                ok: true,
                result: Some(response_result),
                error: None,
            };
            stream
                .write_all(
                    serde_json::to_vec(&response)
                        .expect("serialize control response")
                        .as_slice(),
                )
                .await
                .expect("write response");
            let _ = fs::remove_file(socket_path);
        })
    }

    #[test]
    fn shell_paths_from_roots_uses_explicit_roots() {
        let paths = ShellPaths::from_roots(
            PathBuf::from("/tmp/igloo-shell-config"),
            PathBuf::from("/tmp/igloo-shell-data"),
            PathBuf::from("/tmp/igloo-shell-state"),
        );

        assert_eq!(
            paths.config_dir,
            PathBuf::from("/tmp/igloo-shell-config/igloo-shell")
        );
        assert_eq!(
            paths.data_dir,
            PathBuf::from("/tmp/igloo-shell-data/igloo-shell")
        );
        assert_eq!(
            paths.state_dir,
            PathBuf::from("/tmp/igloo-shell-state/igloo-shell")
        );
        assert_eq!(
            paths.relay_profiles_path,
            PathBuf::from("/tmp/igloo-shell-config/igloo-shell/relay-profiles.json")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn typed_daemon_helpers_decode_runtime_status_diagnostics_and_shutdown() {
        let paths = test_paths("typed-daemon");
        paths.ensure().expect("ensure shell paths");
        let profile_id = "alice";
        let token = "daemon-token";
        let status = sample_runtime_status();
        let config = DeviceConfig::default();

        let status_socket = paths.profile_state_dir(profile_id).join("status.sock");
        write_test_daemon_metadata(&paths, profile_id, &status_socket, token);
        let worker = spawn_fake_daemon_once(
            status_socket.clone(),
            token.to_string(),
            ControlCommand::RuntimeStatus,
            serde_json::to_value(&status).expect("serialize runtime status"),
        )
        .await;
        let decoded = daemon_runtime_status(&paths, profile_id)
            .await
            .expect("typed runtime status");
        assert_eq!(decoded.metadata.share_public_key, "share-pubkey");
        worker.await.expect("join status worker");

        let diagnostics_socket = paths.profile_state_dir(profile_id).join("diagnostics.sock");
        write_test_daemon_metadata(&paths, profile_id, &diagnostics_socket, token);
        let worker = spawn_fake_daemon_once(
            diagnostics_socket.clone(),
            token.to_string(),
            ControlCommand::RuntimeDiagnostics,
            serde_json::to_value(RuntimeDiagnosticsSnapshot {
                runtime_status: RuntimeStatusPayload(status.clone()),
            })
            .expect("serialize diagnostics"),
        )
        .await;
        let diagnostics = daemon_runtime_diagnostics(&paths, profile_id)
            .await
            .expect("typed diagnostics");
        assert_eq!(
            diagnostics.runtime_status.0.metadata.group_public_key,
            "group-pubkey"
        );
        worker.await.expect("join diagnostics worker");

        let metadata_socket = paths.profile_state_dir(profile_id).join("metadata.sock");
        write_test_daemon_metadata(&paths, profile_id, &metadata_socket, token);
        let worker = spawn_fake_daemon_once(
            metadata_socket.clone(),
            token.to_string(),
            ControlCommand::RuntimeMetadata,
            serde_json::to_value(&status.metadata).expect("serialize runtime metadata"),
        )
        .await;
        let metadata = daemon_runtime_metadata(&paths, profile_id)
            .await
            .expect("typed metadata");
        assert_eq!(metadata.share_public_key, "share-pubkey");
        worker.await.expect("join metadata worker");

        let readiness_socket = paths.profile_state_dir(profile_id).join("readiness.sock");
        write_test_daemon_metadata(&paths, profile_id, &readiness_socket, token);
        let worker = spawn_fake_daemon_once(
            readiness_socket.clone(),
            token.to_string(),
            ControlCommand::Readiness,
            serde_json::to_value(&status.readiness).expect("serialize readiness"),
        )
        .await;
        let readiness = daemon_runtime_readiness(&paths, profile_id)
            .await
            .expect("typed readiness");
        assert!(readiness.sign_ready);
        worker.await.expect("join readiness worker");

        let peers_socket = paths.profile_state_dir(profile_id).join("peers.sock");
        write_test_daemon_metadata(&paths, profile_id, &peers_socket, token);
        let worker = spawn_fake_daemon_once(
            peers_socket.clone(),
            token.to_string(),
            ControlCommand::PeerStatus,
            serde_json::to_value(&status.peers).expect("serialize peer status"),
        )
        .await;
        let peers = daemon_peer_status(&paths, profile_id)
            .await
            .expect("typed peer status");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].pubkey, "peer-1");
        worker.await.expect("join peer worker");

        let config_socket = paths.profile_state_dir(profile_id).join("config.sock");
        write_test_daemon_metadata(&paths, profile_id, &config_socket, token);
        let worker = spawn_fake_daemon_once(
            config_socket.clone(),
            token.to_string(),
            ControlCommand::ReadConfig,
            serde_json::to_value(&config).expect("serialize device config"),
        )
        .await;
        let decoded_config = daemon_runtime_config(&paths, profile_id)
            .await
            .expect("typed runtime config");
        assert_eq!(decoded_config.request_ttl_secs, config.request_ttl_secs);
        worker.await.expect("join config worker");

        let shutdown_socket = paths.profile_state_dir(profile_id).join("shutdown.sock");
        write_test_daemon_metadata(&paths, profile_id, &shutdown_socket, token);
        let worker = spawn_fake_daemon_once(
            shutdown_socket.clone(),
            token.to_string(),
            ControlCommand::Shutdown,
            serde_json::to_value(ShutdownPayload { shutdown: true })
                .expect("serialize shutdown payload"),
        )
        .await;
        let result = stop_profile_daemon(&paths, profile_id)
            .await
            .expect("stop profile daemon");
        assert_eq!(result["shutdown"], true);
        assert!(read_daemon_metadata(&paths, profile_id).is_err());
        worker.await.expect("join shutdown worker");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn typed_daemon_helpers_decode_mutation_results() {
        let paths = test_paths("typed-daemon-mutations");
        paths.ensure().expect("ensure shell paths");
        let profile_id = "alice";
        let token = "daemon-token";

        let sign_socket = paths.profile_state_dir(profile_id).join("sign.sock");
        write_test_daemon_metadata(&paths, profile_id, &sign_socket, token);
        let worker = spawn_fake_daemon_once(
            sign_socket.clone(),
            token.to_string(),
            ControlCommand::Sign {
                message_hex32: "11".repeat(32),
                timeout_secs: None,
            },
            serde_json::to_value(SignPayload {
                request_id: "req-sign".to_string(),
                signatures_hex: vec!["aa".repeat(64)],
            })
            .expect("serialize sign payload"),
        )
        .await;
        let sign = daemon_sign(&paths, profile_id, "11".repeat(32))
            .await
            .expect("typed sign");
        assert_eq!(sign.request_id, "req-sign");
        worker.await.expect("join sign worker");

        let ecdh_socket = paths.profile_state_dir(profile_id).join("ecdh.sock");
        write_test_daemon_metadata(&paths, profile_id, &ecdh_socket, token);
        let worker = spawn_fake_daemon_once(
            ecdh_socket.clone(),
            token.to_string(),
            ControlCommand::Ecdh {
                pubkey_hex32: "22".repeat(32),
                timeout_secs: None,
            },
            serde_json::to_value(EcdhPayload {
                request_id: "req-ecdh".to_string(),
                shared_secret_hex32: "bb".repeat(32),
            })
            .expect("serialize ecdh payload"),
        )
        .await;
        let ecdh = daemon_ecdh(&paths, profile_id, "22".repeat(32))
            .await
            .expect("typed ecdh");
        assert_eq!(ecdh.shared_secret_hex32, "bb".repeat(32));
        worker.await.expect("join ecdh worker");

        let ping_socket = paths.profile_state_dir(profile_id).join("ping.sock");
        write_test_daemon_metadata(&paths, profile_id, &ping_socket, token);
        let worker = spawn_fake_daemon_once(
            ping_socket.clone(),
            token.to_string(),
            ControlCommand::Ping {
                peer: "peer-1".to_string(),
                timeout_secs: None,
            },
            serde_json::to_value(PingPayload {
                request_id: "req-ping".to_string(),
                peer: "peer-1".to_string(),
            })
            .expect("serialize ping payload"),
        )
        .await;
        let ping = daemon_ping(&paths, profile_id, "peer-1".to_string())
            .await
            .expect("typed ping");
        assert_eq!(ping.peer, "peer-1");
        worker.await.expect("join ping worker");

        let onboard_socket = paths.profile_state_dir(profile_id).join("onboard.sock");
        write_test_daemon_metadata(&paths, profile_id, &onboard_socket, token);
        let worker = spawn_fake_daemon_once(
            onboard_socket.clone(),
            token.to_string(),
            ControlCommand::Onboard {
                peer: "peer-1".to_string(),
                timeout_secs: None,
            },
            serde_json::to_value(OnboardPayload {
                request_id: "req-onboard".to_string(),
                group_member_count: 2,
            })
            .expect("serialize onboard payload"),
        )
        .await;
        let onboard = daemon_onboard(&paths, profile_id, "peer-1".to_string())
            .await
            .expect("typed onboard");
        assert_eq!(onboard.group_member_count, 2);
        worker.await.expect("join onboard worker");

        let wipe_socket = paths.profile_state_dir(profile_id).join("wipe.sock");
        write_test_daemon_metadata(&paths, profile_id, &wipe_socket, token);
        let worker = spawn_fake_daemon_once(
            wipe_socket.clone(),
            token.to_string(),
            ControlCommand::WipeState,
            serde_json::to_value(WipedPayload { wiped: true }).expect("serialize wipe payload"),
        )
        .await;
        let wipe = daemon_wipe_state(&paths, profile_id)
            .await
            .expect("typed wipe");
        assert!(wipe.wiped);
        worker.await.expect("join wipe worker");

        let policy_socket = paths.profile_state_dir(profile_id).join("policy.sock");
        write_test_daemon_metadata(&paths, profile_id, &policy_socket, token);
        let policy_override = PeerPolicyOverride::default();
        let worker = spawn_fake_daemon_once(
            policy_socket.clone(),
            token.to_string(),
            ControlCommand::SetPolicyOverride {
                peer: "peer-1".to_string(),
                policy_override_json: serde_json::to_string(&policy_override)
                    .expect("serialize policy override"),
            },
            serde_json::to_value(UpdatedPayload { updated: true })
                .expect("serialize updated payload"),
        )
        .await;
        let updated =
            daemon_set_policy_override(&paths, profile_id, "peer-1".to_string(), &policy_override)
                .await
                .expect("typed policy update");
        assert!(updated.updated);
        worker.await.expect("join policy worker");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_profile_runtime_uses_typed_runtime_status_fields() {
        let paths = test_paths("check-runtime");
        paths.ensure().expect("ensure shell paths");
        replace_relay_profile(
            &paths,
            RelayProfile {
                id: "local".to_string(),
                label: "Local".to_string(),
                relays: vec!["ws://127.0.0.1:65535".to_string()],
            },
        )
        .expect("write relay profile");

        let profile = build_profile_manifest(
            &paths,
            "alice",
            "Alice".to_string(),
            "/tmp/group.json".to_string(),
            "/tmp/share.json".to_string(),
            "local".to_string(),
            now_unix_secs(),
        );
        fs::create_dir_all(paths.profile_state_dir(&profile.id)).expect("create state dir");
        write_profile(&paths, &profile).expect("write profile");

        let socket_path = paths.profile_state_dir(&profile.id).join("runtime.sock");
        write_test_daemon_metadata(&paths, &profile.id, &socket_path, "daemon-token");
        let worker = spawn_fake_daemon_once(
            socket_path.clone(),
            "daemon-token".to_string(),
            ControlCommand::RuntimeStatus,
            serde_json::to_value(sample_runtime_status()).expect("serialize runtime status"),
        )
        .await;

        let result = check_profile_runtime(&paths, &profile.id, ShellCheckKind::Sign)
            .await
            .expect("check runtime");
        assert!(result.runtime_online);
        assert_eq!(result.share_public_key.as_deref(), Some("share-pubkey"));
        assert_eq!(result.group_public_key.as_deref(), Some("group-pubkey"));
        assert_eq!(result.details["sign_initiator_peer_count"], json!(1));
        assert!(
            result
                .reasons_not_ready
                .iter()
                .any(|reason| reason == "no_connected_relays")
        );
        worker.await.expect("join runtime worker");
    }

    fn sample_group() -> GroupPackage {
        GroupPackage {
            group_name: "Shell Test Group".to_string(),
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
        let encrypted_profile = store_encrypted_profile(
            &paths,
            "share_package",
            "test",
            &share_raw,
            Some("encrypted-profile-pass".to_string()),
        )
        .expect("store share");
        let profile = build_profile_manifest(
            &paths,
            "alice",
            "Alice".to_string(),
            group_ref,
            encrypted_profile.id.clone(),
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
    async fn onboarding_import_writes_final_profile_and_encrypted_profile() {
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

        let bundle = create_keyset(CreateKeysetConfig::new("Test Group", 2, 3))
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

        let result = onboarding::import_profile_from_onboarding_value_with(
            &paths,
            &encoded,
            Some("Alice".to_string()),
            Some("local".to_string()),
            Some("encrypted-profile-pass".to_string()),
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
            encrypted_profile,
            ..
        } = result
        else {
            panic!("expected final profile import result");
        };

        assert_eq!(profile.encrypted_profile_ref, encrypted_profile.id);
        assert!(Path::new(&profile.group_ref).exists());
        let share_raw = load_share_payload_with_passphrase(
            &paths,
            &profile,
            Some("encrypted-profile-pass".to_string()),
        )
        .expect("decrypt share payload");
        let parsed_share = parse_share_package(&share_raw).expect("parse stored share");
        assert_eq!(parsed_share.idx, share.idx);
        assert!(read_encrypted_profile(&paths, &encrypted_profile.id).is_ok());
        let store = bifrost_app::runtime::EncryptedFileStore::new(
            PathBuf::from(&profile.state_path),
            share.clone(),
        );
        let state = store.load().expect("load saved onboarding state");
        let peer_stats = state.nonce_pool.peer_stats(1);
        assert_eq!(peer_stats.incoming_available, 1);
        assert!(peer_stats.outgoing_available >= 4);

        unsafe {
            std::env::set_var(PROFILE_PASSPHRASE_ENV, "encrypted-profile-pass");
        }
        let (_resolved_profile, resolved) =
            resolve_profile_runtime(&paths, &profile.id).expect("resolve runtime");
        unsafe {
            std::env::remove_var(PROFILE_PASSPHRASE_ENV);
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

        let bundle = create_keyset(CreateKeysetConfig::new("Test Group", 2, 3))
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
            Some("encrypted-profile-pass".to_string()),
        )
        .expect("import raw profile");
        let ProfileImportResult::ProfileCreated { profile, .. } = import else {
            panic!("expected profile created");
        };

        let exported = export_profile_as_bfprofile(
            &paths,
            &profile.id,
            "package-pass".to_string(),
            Some("encrypted-profile-pass".to_string()),
            None,
        )
        .expect("export bfprofile");
        let imported = import_profile_from_bfprofile_value(
            &paths,
            &exported.package,
            "package-pass".to_string(),
            Some("Recovered".to_string()),
            Some("local".to_string()),
            Some("encrypted-profile-pass".to_string()),
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
            Some("encrypted-profile-pass".to_string()),
        )
        .expect("unlock imported bfprofile");
    }
}
