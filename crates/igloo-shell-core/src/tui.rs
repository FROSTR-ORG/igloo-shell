use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bifrost_app::host::ControlCommand;
use bifrost_core::types::{PeerPolicyOverride, PolicyOverrideValue};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use frostr_utils::BfProfilePayload;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    Tabs, Wrap,
};
use serde::Deserialize;

use crate::shell::{
    ConnectedOnboardingImport, GeneratedKeysetDraft, PolicyDirection, PolicyMethod,
    ProfileImportResult, ProfileManifest, ProfilePreview, ShellPaths,
    connect_onboarding_package_preview, create_generated_keyset_draft, daemon_log_path,
    daemon_runtime_query, export_generated_onboarding_package,
    finalize_connected_onboarding_import, import_generated_share,
    import_profile_from_bfprofile_payload, list_profiles, now_unix_secs, preview_bfprofile_value,
    preview_bfshare_recovery, read_daemon_metadata, read_profile,
    set_profile_default_policy_override, set_profile_peer_policy_override,
    start_profile_daemon_with_passphrase, stop_profile_daemon,
    validate_profile_unlock_with_passphrase,
};

const LOG_TAIL_LINES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppMode {
    LoggedOut,
    LoggedIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusRegion {
    Tabs,
    Content,
    Actions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoggedOutView {
    Home,
    OnboardConnect,
    OnboardSave,
    ImportConnect,
    ImportSave,
    RecoverConnect,
    RecoverSave,
    GenerateConfig,
    GenerateProfile,
    GenerateDistribute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoggedInTab {
    Dashboard,
    Permissions,
    Settings,
}

impl LoggedInTab {
    fn all() -> [LoggedInTab; 3] {
        [
            LoggedInTab::Dashboard,
            LoggedInTab::Permissions,
            LoggedInTab::Settings,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            LoggedInTab::Dashboard => "Dashboard",
            LoggedInTab::Permissions => "Permissions",
            LoggedInTab::Settings => "Settings",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HomeAction {
    OnboardPackage,
    ImportExisting,
    RecoverShare,
    GenerateKeyset,
}

impl HomeAction {
    fn all() -> [HomeAction; 4] {
        [
            HomeAction::OnboardPackage,
            HomeAction::ImportExisting,
            HomeAction::RecoverShare,
            HomeAction::GenerateKeyset,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            HomeAction::OnboardPackage => "Onboard Package",
            HomeAction::ImportExisting => "Import Existing",
            HomeAction::RecoverShare => "Recover Share",
            HomeAction::GenerateKeyset => "Generate Keyset",
        }
    }

    fn description(self) -> &'static str {
        match self {
            HomeAction::OnboardPackage => {
                "Connect a password-protected bfonboard package and save this device."
            }
            HomeAction::ImportExisting => {
                "Import a bfprofile package from pasted text or a local path."
            }
            HomeAction::RecoverShare => {
                "Recover a device from a bfshare package and the published backup."
            }
            HomeAction::GenerateKeyset => {
                "Create a fresh keyset, save this local device, and export onboarding packages for the remaining shares."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionsAction {
    NextField,
    CyclePolicy,
    ClearOverride,
    PingPeer,
    OnboardPeer,
    Refresh,
}

impl PermissionsAction {
    fn all() -> [PermissionsAction; 6] {
        [
            PermissionsAction::NextField,
            PermissionsAction::CyclePolicy,
            PermissionsAction::ClearOverride,
            PermissionsAction::PingPeer,
            PermissionsAction::OnboardPeer,
            PermissionsAction::Refresh,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            PermissionsAction::NextField => "Next Field",
            PermissionsAction::CyclePolicy => "Cycle Policy",
            PermissionsAction::ClearOverride => "Clear Override",
            PermissionsAction::PingPeer => "Ping Peer",
            PermissionsAction::OnboardPeer => "Onboard Peer",
            PermissionsAction::Refresh => "Refresh",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyField {
    RequestPing,
    RequestOnboard,
    RequestSign,
    RequestEcdh,
    RespondPing,
    RespondOnboard,
    RespondSign,
    RespondEcdh,
}

impl PolicyField {
    fn all() -> [PolicyField; 8] {
        [
            PolicyField::RequestPing,
            PolicyField::RequestOnboard,
            PolicyField::RequestSign,
            PolicyField::RequestEcdh,
            PolicyField::RespondPing,
            PolicyField::RespondOnboard,
            PolicyField::RespondSign,
            PolicyField::RespondEcdh,
        ]
    }

    fn short_label(self) -> &'static str {
        match self {
            PolicyField::RequestPing => "rq.ping",
            PolicyField::RequestOnboard => "rq.onbd",
            PolicyField::RequestSign => "rq.sign",
            PolicyField::RequestEcdh => "rq.ecdh",
            PolicyField::RespondPing => "rs.ping",
            PolicyField::RespondOnboard => "rs.onbd",
            PolicyField::RespondSign => "rs.sign",
            PolicyField::RespondEcdh => "rs.ecdh",
        }
    }

    fn direction(self) -> PolicyDirection {
        match self {
            PolicyField::RequestPing
            | PolicyField::RequestOnboard
            | PolicyField::RequestSign
            | PolicyField::RequestEcdh => PolicyDirection::Request,
            PolicyField::RespondPing
            | PolicyField::RespondOnboard
            | PolicyField::RespondSign
            | PolicyField::RespondEcdh => PolicyDirection::Respond,
        }
    }

    fn method(self) -> PolicyMethod {
        match self {
            PolicyField::RequestPing | PolicyField::RespondPing => PolicyMethod::Ping,
            PolicyField::RequestOnboard | PolicyField::RespondOnboard => PolicyMethod::Onboard,
            PolicyField::RequestSign | PolicyField::RespondSign => PolicyMethod::Sign,
            PolicyField::RequestEcdh | PolicyField::RespondEcdh => PolicyMethod::Ecdh,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsAction {
    Refresh,
    StartStopDaemon,
    ToggleLogDetail,
    Logout,
}

impl SettingsAction {
    fn all() -> [SettingsAction; 4] {
        [
            SettingsAction::Refresh,
            SettingsAction::StartStopDaemon,
            SettingsAction::ToggleLogDetail,
            SettingsAction::Logout,
        ]
    }
}

#[derive(Debug, Clone)]
struct InputModal {
    title: String,
    description: String,
    target: InputTarget,
    input: String,
    secret: bool,
    error: Option<String>,
}

#[derive(Debug, Clone)]
enum InputTarget {
    UnlockSecret,
    OnboardPackageInput,
    OnboardSecret,
    OnboardLabel,
    OnboardVaultSecret,
    OnboardVaultConfirm,
    ImportPackageInput,
    ImportSecret,
    ImportLabel,
    ImportVaultSecret,
    ImportVaultConfirm,
    RecoverPackageInput,
    RecoverSecret,
    RecoverLabel,
    RecoverVaultSecret,
    RecoverVaultConfirm,
    GenerateKeysetName,
    GenerateThreshold,
    GenerateCount,
    GenerateLocalLabel,
    GenerateRelayUrls,
    GenerateVaultSecret,
    GenerateVaultConfirm,
    GenerateDistributionSecret,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct DeviceStatusView {
    device_id: String,
    pending_ops: usize,
    last_active: u64,
    known_peers: usize,
    request_seq: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct RuntimeMetadataView {
    device_id: String,
    member_idx: u16,
    share_public_key: String,
    group_public_key: String,
    peers: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct RuntimeReadinessView {
    runtime_ready: bool,
    restore_complete: bool,
    sign_ready: bool,
    ecdh_ready: bool,
    threshold: usize,
    signing_peer_count: usize,
    ecdh_peer_count: usize,
    last_refresh_at: Option<u64>,
    degraded_reasons: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PeerStatusView {
    idx: u16,
    pubkey: String,
    known: bool,
    last_seen: Option<u64>,
    online: bool,
    incoming_available: usize,
    outgoing_available: usize,
    outgoing_spent: usize,
    can_sign: bool,
    should_send_nonces: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PendingOperationView {
    op_type: String,
    request_id: String,
    started_at: u64,
    timeout_at: u64,
    target_peers: Vec<String>,
    threshold: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct RuntimeStatusView {
    status: DeviceStatusView,
    metadata: RuntimeMetadataView,
    readiness: RuntimeReadinessView,
    peers: Vec<PeerStatusView>,
    #[serde(default)]
    peer_permission_states: Vec<PeerPermissionStateView>,
    pending_operations: Vec<PendingOperationView>,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerPermissionStateView {
    pubkey: String,
    manual_override: PeerPolicyOverride,
    remote_observation: Option<RemoteObservationView>,
    effective_policy: EffectivePolicyView,
}

#[derive(Debug, Clone, Deserialize)]
struct EffectivePolicyView {
    request: MethodPolicyView,
    respond: MethodPolicyView,
}

#[derive(Debug, Clone, Deserialize)]
struct MethodPolicyView {
    ping: bool,
    onboard: bool,
    sign: bool,
    ecdh: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RemoteObservationView {
    request: MethodPolicyView,
    respond: MethodPolicyView,
    updated: u64,
    revision: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyOverridesDocument {
    #[serde(default)]
    default_override: Option<PeerPolicyOverride>,
    #[serde(default)]
    peer_overrides: Vec<PolicyPeerOverride>,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyPeerOverride {
    pubkey: String,
    #[serde(default)]
    policy_override: PeerPolicyOverride,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct DaemonSnapshot {
    runtime: RuntimeStatusView,
}

#[derive(Debug, Clone, Default)]
pub struct TuiLaunchOptions {
    pub profile_id: Option<String>,
    pub initial_vault_secret: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct OnboardConnectState {
    package_input: String,
    onboarding_secret: String,
}

#[derive(Debug, Clone, Default)]
struct OnboardSaveState {
    connection: Option<ConnectedOnboardingImport>,
    label: String,
    vault_secret: String,
    vault_confirm: String,
}

#[derive(Debug, Clone, Default)]
struct ImportConnectState {
    package_input: String,
    package_secret: String,
}

#[derive(Debug, Clone, Default)]
struct PendingImportState {
    preview: Option<ProfilePreview>,
    payload: Option<BfProfilePayload>,
    label: String,
    vault_secret: String,
    vault_confirm: String,
}

#[derive(Debug, Clone, Default)]
struct RecoverConnectState {
    package_input: String,
    package_secret: String,
}

#[derive(Debug, Clone, Default)]
struct GenerateConfigState {
    keyset_name: String,
    threshold: String,
    count: String,
}

#[derive(Debug, Clone)]
struct GenerateProfileState {
    draft: GeneratedKeysetDraft,
    share_cursor: usize,
    label: String,
    relay_urls: String,
    vault_secret: String,
    vault_confirm: String,
    distribution_secret: String,
}

#[derive(Debug, Clone)]
struct GeneratedPackageView {
    member_idx: u16,
    label: String,
    path: String,
    package_text: String,
}

#[derive(Debug, Clone)]
struct GenerateDistributeState {
    profile: ProfileManifest,
    vault_secret: String,
    packages: Vec<GeneratedPackageView>,
    cursor: usize,
}

struct App {
    mode: AppMode,
    focus_region: FocusRegion,
    profiles: Vec<ProfileManifest>,
    profile_cursor: usize,
    home_action_cursor: usize,
    row_cursor: usize,
    permission_field_cursor: usize,
    action_cursor: usize,
    settings_cursor: usize,
    logged_out_view: LoggedOutView,
    logged_in_tab: LoggedInTab,
    active_profile_id: Option<String>,
    active_profile: Option<ProfileManifest>,
    preferred_profile_id: Option<String>,
    snapshot: Option<DaemonSnapshot>,
    daemon_running: bool,
    status_line: String,
    last_refresh_at: Option<u64>,
    logs_verbose: bool,
    log_lines: Vec<String>,
    last_export_path: Option<String>,
    should_quit: bool,
    session_vault_secrets: BTreeMap<String, String>,
    input_modal: Option<InputModal>,
    onboard_connect: OnboardConnectState,
    onboard_save: OnboardSaveState,
    import_connect: ImportConnectState,
    import_save: PendingImportState,
    recover_connect: RecoverConnectState,
    recover_save: PendingImportState,
    generate_config: GenerateConfigState,
    generate_profile: Option<GenerateProfileState>,
    generate_distribute: Option<GenerateDistributeState>,
}

impl App {
    fn new(options: TuiLaunchOptions) -> Self {
        let preferred_profile_id = options.profile_id.clone();
        Self {
            mode: AppMode::LoggedOut,
            focus_region: FocusRegion::Content,
            profiles: Vec::new(),
            profile_cursor: 0,
            home_action_cursor: 0,
            row_cursor: 0,
            permission_field_cursor: 0,
            action_cursor: 0,
            settings_cursor: 0,
            logged_out_view: LoggedOutView::Home,
            logged_in_tab: LoggedInTab::Dashboard,
            active_profile_id: None,
            active_profile: None,
            preferred_profile_id,
            snapshot: None,
            daemon_running: false,
            status_line: "Arrows move. Enter selects. Esc goes back. q quits.".to_string(),
            last_refresh_at: None,
            logs_verbose: false,
            log_lines: Vec::new(),
            last_export_path: None,
            should_quit: false,
            session_vault_secrets: options
                .profile_id
                .zip(options.initial_vault_secret)
                .into_iter()
                .collect(),
            input_modal: None,
            onboard_connect: OnboardConnectState::default(),
            onboard_save: OnboardSaveState::default(),
            import_connect: ImportConnectState::default(),
            import_save: PendingImportState::default(),
            recover_connect: RecoverConnectState::default(),
            recover_save: PendingImportState::default(),
            generate_config: GenerateConfigState::default(),
            generate_profile: None,
            generate_distribute: None,
        }
    }
}

pub async fn run_tui_with_options(paths: &ShellPaths, options: TuiLaunchOptions) -> Result<()> {
    let mut app = App::new(options);
    refresh(paths, &mut app).await?;
    prepare_initial_state(paths, &mut app).await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = tui_loop(paths, &mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn tui_loop(
    paths: &ShellPaths,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|frame| render(frame, app))?;
        if app.should_quit {
            return Ok(());
        }
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            handle_key(paths, app, key.code, key.modifiers).await?;
        }
    }
}

async fn handle_key(
    paths: &ShellPaths,
    app: &mut App,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Result<()> {
    if app.input_modal.is_some() {
        return handle_input_modal_key(paths, app, code).await;
    }

    if matches!(code, KeyCode::Char('q')) {
        app.should_quit = true;
        return Ok(());
    }

    match app.mode {
        AppMode::LoggedOut => handle_logged_out_key(paths, app, code, modifiers).await,
        AppMode::LoggedIn => handle_logged_in_key(paths, app, code, modifiers).await,
    }
}

async fn handle_logged_out_key(
    paths: &ShellPaths,
    app: &mut App,
    code: KeyCode,
    _modifiers: KeyModifiers,
) -> Result<()> {
    match app.logged_out_view {
        LoggedOutView::Home => match code {
            KeyCode::Left => {
                app.focus_region = FocusRegion::Content;
            }
            KeyCode::Right => {
                app.focus_region = FocusRegion::Actions;
            }
            KeyCode::Up => {
                if app.focus_region == FocusRegion::Actions {
                    app.home_action_cursor = app.home_action_cursor.saturating_sub(1);
                } else {
                    app.profile_cursor = app.profile_cursor.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if app.focus_region == FocusRegion::Actions {
                    app.home_action_cursor =
                        (app.home_action_cursor + 1).min(HomeAction::all().len().saturating_sub(1));
                } else if !app.profiles.is_empty() {
                    app.profile_cursor = (app.profile_cursor + 1).min(app.profiles.len() - 1);
                }
            }
            KeyCode::Enter => {
                if app.focus_region == FocusRegion::Actions {
                    let action = HomeAction::all()[app.home_action_cursor];
                    open_home_action(app, action);
                } else if !app.profiles.is_empty() {
                    open_input_modal(
                        app,
                        InputTarget::UnlockSecret,
                        "Unlock Profile",
                        "Type the vault secret for the selected profile to log in and start the daemon.",
                        String::new(),
                        true,
                    );
                }
            }
            KeyCode::Esc => {
                app.focus_region = FocusRegion::Content;
            }
            _ => {}
        },
        LoggedOutView::OnboardConnect => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(3),
            KeyCode::Enter => match app.row_cursor {
                0 => open_input_modal(
                    app,
                    InputTarget::OnboardPackageInput,
                    "Onboarding Package",
                    "Paste a bfonboard package or type a filesystem path to one.",
                    app.onboard_connect.package_input.clone(),
                    false,
                ),
                1 => open_input_modal(
                    app,
                    InputTarget::OnboardSecret,
                    "Onboarding Secret",
                    "Type the secret that decrypts the onboarding package.",
                    app.onboard_connect.onboarding_secret.clone(),
                    true,
                ),
                2 => connect_onboarding(paths, app).await?,
                3 => return_to_home(app),
                _ => {}
            },
            KeyCode::Esc => return_to_home(app),
            _ => {}
        },
        LoggedOutView::OnboardSave => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(4),
            KeyCode::Enter => match app.row_cursor {
                0 => open_input_modal(
                    app,
                    InputTarget::OnboardLabel,
                    "Profile Name",
                    "Choose the local profile label shown in igloo-shell.",
                    app.onboard_save.label.clone(),
                    false,
                ),
                1 => open_input_modal(
                    app,
                    InputTarget::OnboardVaultSecret,
                    "Vault Secret",
                    "Type the local vault secret used to encrypt imported secrets on this device.",
                    app.onboard_save.vault_secret.clone(),
                    true,
                ),
                2 => open_input_modal(
                    app,
                    InputTarget::OnboardVaultConfirm,
                    "Confirm Vault Secret",
                    "Re-type the local vault secret.",
                    app.onboard_save.vault_confirm.clone(),
                    true,
                ),
                3 => save_onboarded_profile(paths, app).await?,
                4 => {
                    app.logged_out_view = LoggedOutView::OnboardConnect;
                    app.row_cursor = 0;
                }
                _ => {}
            },
            KeyCode::Esc => {
                app.logged_out_view = LoggedOutView::OnboardConnect;
                app.row_cursor = 0;
            }
            _ => {}
        },
        LoggedOutView::ImportConnect => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(3),
            KeyCode::Enter => match app.row_cursor {
                0 => open_input_modal(
                    app,
                    InputTarget::ImportPackageInput,
                    "bfprofile Input",
                    "Paste a bfprofile package or type a filesystem path to one.",
                    app.import_connect.package_input.clone(),
                    false,
                ),
                1 => open_input_modal(
                    app,
                    InputTarget::ImportSecret,
                    "Package Secret",
                    "Type the secret that decrypts the bfprofile package.",
                    app.import_connect.package_secret.clone(),
                    true,
                ),
                2 => connect_bfprofile_import(app)?,
                3 => return_to_home(app),
                _ => {}
            },
            KeyCode::Esc => return_to_home(app),
            _ => {}
        },
        LoggedOutView::ImportSave => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(4),
            KeyCode::Enter => match app.row_cursor {
                0 => open_input_modal(
                    app,
                    InputTarget::ImportLabel,
                    "Profile Name",
                    "Choose the local profile label shown in igloo-shell.",
                    app.import_save.label.clone(),
                    false,
                ),
                1 => open_input_modal(
                    app,
                    InputTarget::ImportVaultSecret,
                    "Vault Secret",
                    "Type the local vault secret used to encrypt the imported share.",
                    app.import_save.vault_secret.clone(),
                    true,
                ),
                2 => open_input_modal(
                    app,
                    InputTarget::ImportVaultConfirm,
                    "Confirm Vault Secret",
                    "Re-type the local vault secret.",
                    app.import_save.vault_confirm.clone(),
                    true,
                ),
                3 => save_imported_profile(paths, app).await?,
                4 => {
                    app.logged_out_view = LoggedOutView::ImportConnect;
                    app.row_cursor = 0;
                }
                _ => {}
            },
            KeyCode::Esc => {
                app.logged_out_view = LoggedOutView::ImportConnect;
                app.row_cursor = 0;
            }
            _ => {}
        },
        LoggedOutView::RecoverConnect => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(3),
            KeyCode::Enter => match app.row_cursor {
                0 => open_input_modal(
                    app,
                    InputTarget::RecoverPackageInput,
                    "bfshare Input",
                    "Paste a bfshare package or type a filesystem path to one.",
                    app.recover_connect.package_input.clone(),
                    false,
                ),
                1 => open_input_modal(
                    app,
                    InputTarget::RecoverSecret,
                    "Share Secret",
                    "Type the secret that decrypts the bfshare package.",
                    app.recover_connect.package_secret.clone(),
                    true,
                ),
                2 => connect_bfshare_recovery(app).await?,
                3 => return_to_home(app),
                _ => {}
            },
            KeyCode::Esc => return_to_home(app),
            _ => {}
        },
        LoggedOutView::RecoverSave => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(4),
            KeyCode::Enter => match app.row_cursor {
                0 => open_input_modal(
                    app,
                    InputTarget::RecoverLabel,
                    "Profile Name",
                    "Choose the local profile label shown in igloo-shell.",
                    app.recover_save.label.clone(),
                    false,
                ),
                1 => open_input_modal(
                    app,
                    InputTarget::RecoverVaultSecret,
                    "Vault Secret",
                    "Type the local vault secret used to encrypt the recovered share.",
                    app.recover_save.vault_secret.clone(),
                    true,
                ),
                2 => open_input_modal(
                    app,
                    InputTarget::RecoverVaultConfirm,
                    "Confirm Vault Secret",
                    "Re-type the local vault secret.",
                    app.recover_save.vault_confirm.clone(),
                    true,
                ),
                3 => save_recovered_profile(paths, app).await?,
                4 => {
                    app.logged_out_view = LoggedOutView::RecoverConnect;
                    app.row_cursor = 0;
                }
                _ => {}
            },
            KeyCode::Esc => {
                app.logged_out_view = LoggedOutView::RecoverConnect;
                app.row_cursor = 0;
            }
            _ => {}
        },
        LoggedOutView::GenerateConfig => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(4),
            KeyCode::Enter => match app.row_cursor {
                0 => open_input_modal(
                    app,
                    InputTarget::GenerateKeysetName,
                    "Keyset Name",
                    "Type a shared name for this new keyset.",
                    app.generate_config.keyset_name.clone(),
                    false,
                ),
                1 => open_input_modal(
                    app,
                    InputTarget::GenerateThreshold,
                    "Threshold",
                    "Type the signing threshold for this keyset.",
                    app.generate_config.threshold.clone(),
                    false,
                ),
                2 => open_input_modal(
                    app,
                    InputTarget::GenerateCount,
                    "Member Count",
                    "Type the total number of shares to generate.",
                    app.generate_config.count.clone(),
                    false,
                ),
                3 => create_generate_draft(app)?,
                4 => return_to_home(app),
                _ => {}
            },
            KeyCode::Esc => return_to_home(app),
            _ => {}
        },
        LoggedOutView::GenerateProfile => match code {
            KeyCode::Up => app.row_cursor = app.row_cursor.saturating_sub(1),
            KeyCode::Down => app.row_cursor = (app.row_cursor + 1).min(7),
            KeyCode::Enter => match app.row_cursor {
                0 => cycle_generated_share(app),
                1 => {
                    let value = app
                        .generate_profile
                        .as_ref()
                        .map(|state| state.label.clone())
                        .unwrap_or_default();
                    open_input_modal(
                        app,
                        InputTarget::GenerateLocalLabel,
                        "Profile Name",
                        "Choose the local profile label shown in igloo-shell.",
                        value,
                        false,
                    );
                }
                2 => {
                    let value = app
                        .generate_profile
                        .as_ref()
                        .map(|state| state.relay_urls.clone())
                        .unwrap_or_default();
                    open_input_modal(
                        app,
                        InputTarget::GenerateRelayUrls,
                        "Relay URLs",
                        "Type relay URLs separated by commas or spaces.",
                        value,
                        false,
                    );
                }
                3 => {
                    let value = app
                        .generate_profile
                        .as_ref()
                        .map(|state| state.vault_secret.clone())
                        .unwrap_or_default();
                    open_input_modal(
                        app,
                        InputTarget::GenerateVaultSecret,
                        "Vault Secret",
                        "Type the local vault secret used to encrypt this generated share.",
                        value,
                        true,
                    );
                }
                4 => {
                    let value = app
                        .generate_profile
                        .as_ref()
                        .map(|state| state.vault_confirm.clone())
                        .unwrap_or_default();
                    open_input_modal(
                        app,
                        InputTarget::GenerateVaultConfirm,
                        "Confirm Vault Secret",
                        "Re-type the local vault secret.",
                        value,
                        true,
                    );
                }
                5 => {
                    let value = app
                        .generate_profile
                        .as_ref()
                        .map(|state| state.distribution_secret.clone())
                        .unwrap_or_default();
                    open_input_modal(
                        app,
                        InputTarget::GenerateDistributionSecret,
                        "Onboarding Secret",
                        "Type the shared secret used to encrypt onboarding packages for the remaining shares.",
                        value,
                        true,
                    );
                }
                6 => save_generated_profile(paths, app).await?,
                7 => {
                    app.logged_out_view = LoggedOutView::GenerateConfig;
                    app.row_cursor = 0;
                }
                _ => {}
            },
            KeyCode::Esc => {
                app.logged_out_view = LoggedOutView::GenerateConfig;
                app.row_cursor = 0;
            }
            _ => {}
        },
        LoggedOutView::GenerateDistribute => match code {
            KeyCode::Up => {
                if let Some(state) = app.generate_distribute.as_mut() {
                    state.cursor = state.cursor.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if let Some(state) = app.generate_distribute.as_mut() {
                    let max = state.packages.len();
                    state.cursor = (state.cursor + 1).min(max);
                }
            }
            KeyCode::Enter => {
                if let Some(state) = &app.generate_distribute {
                    if state.cursor >= state.packages.len() {
                        let profile_id = state.profile.id.clone();
                        let vault_secret = state.vault_secret.clone();
                        activate_profile_with_secret(paths, app, &profile_id, vault_secret).await?;
                    }
                }
            }
            KeyCode::Esc => {
                if let Some(state) = &app.generate_distribute {
                    let profile_id = state.profile.id.clone();
                    let vault_secret = state.vault_secret.clone();
                    activate_profile_with_secret(paths, app, &profile_id, vault_secret).await?;
                }
            }
            _ => {}
        },
    }
    Ok(())
}

async fn handle_logged_in_key(
    paths: &ShellPaths,
    app: &mut App,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Result<()> {
    match code {
        KeyCode::Tab | KeyCode::Right if app.focus_region == FocusRegion::Tabs => {
            next_tab(app);
        }
        KeyCode::BackTab | KeyCode::Left if app.focus_region == FocusRegion::Tabs => {
            prev_tab(app);
        }
        KeyCode::Down if app.focus_region == FocusRegion::Tabs => {
            app.focus_region = FocusRegion::Content;
        }
        KeyCode::Enter if app.focus_region == FocusRegion::Tabs => {
            app.focus_region = FocusRegion::Content;
        }
        KeyCode::Esc => handle_logged_in_escape(paths, app).await?,
        KeyCode::Left => handle_logged_in_left(app, modifiers),
        KeyCode::Right => handle_logged_in_right(app, modifiers),
        KeyCode::Up => handle_logged_in_up(app),
        KeyCode::Down => handle_logged_in_down(app),
        KeyCode::Enter => handle_logged_in_enter(paths, app).await?,
        _ => {}
    }
    Ok(())
}

fn handle_logged_in_left(app: &mut App, modifiers: KeyModifiers) {
    if modifiers.contains(KeyModifiers::SHIFT) {
        prev_tab(app);
        return;
    }
    match app.focus_region {
        FocusRegion::Tabs => prev_tab(app),
        FocusRegion::Actions => app.focus_region = FocusRegion::Content,
        FocusRegion::Content => {}
    }
}

fn handle_logged_in_right(app: &mut App, modifiers: KeyModifiers) {
    if modifiers.contains(KeyModifiers::SHIFT) {
        next_tab(app);
        return;
    }
    match app.focus_region {
        FocusRegion::Tabs => next_tab(app),
        FocusRegion::Content => {
            if app.logged_in_tab == LoggedInTab::Permissions {
                app.focus_region = FocusRegion::Actions;
            }
        }
        FocusRegion::Actions => {}
    }
}

fn handle_logged_in_up(app: &mut App) {
    match app.focus_region {
        FocusRegion::Tabs => {}
        FocusRegion::Content => match app.logged_in_tab {
            LoggedInTab::Dashboard => app.focus_region = FocusRegion::Tabs,
            LoggedInTab::Permissions => {
                if app.row_cursor == 0 {
                    app.focus_region = FocusRegion::Tabs;
                } else {
                    app.row_cursor = app.row_cursor.saturating_sub(1);
                }
            }
            LoggedInTab::Settings => {
                if app.settings_cursor == 0 {
                    app.focus_region = FocusRegion::Tabs;
                } else {
                    app.settings_cursor = app.settings_cursor.saturating_sub(1);
                }
            }
        },
        FocusRegion::Actions => {
            if app.action_cursor == 0 {
                app.focus_region = FocusRegion::Content;
            } else {
                app.action_cursor = app.action_cursor.saturating_sub(1);
            }
        }
    }
}

fn handle_logged_in_down(app: &mut App) {
    match app.focus_region {
        FocusRegion::Tabs => app.focus_region = FocusRegion::Content,
        FocusRegion::Content => match app.logged_in_tab {
            LoggedInTab::Dashboard => {}
            LoggedInTab::Permissions => {
                let max = permission_row_count(app);
                if max > 0 {
                    app.row_cursor = (app.row_cursor + 1).min(max - 1);
                }
            }
            LoggedInTab::Settings => {
                app.settings_cursor =
                    (app.settings_cursor + 1).min(SettingsAction::all().len().saturating_sub(1));
            }
        },
        FocusRegion::Actions => {
            app.action_cursor =
                (app.action_cursor + 1).min(PermissionsAction::all().len().saturating_sub(1));
        }
    }
}

async fn handle_logged_in_escape(paths: &ShellPaths, app: &mut App) -> Result<()> {
    match app.focus_region {
        FocusRegion::Actions => {
            app.focus_region = FocusRegion::Content;
            app.status_line = "Returned to the selected view.".to_string();
        }
        FocusRegion::Content if app.logged_in_tab != LoggedInTab::Dashboard => {
            app.logged_in_tab = LoggedInTab::Dashboard;
            app.focus_region = FocusRegion::Content;
            app.action_cursor = 0;
            app.row_cursor = 0;
            app.settings_cursor = 0;
            app.status_line = "Returned to Dashboard.".to_string();
        }
        FocusRegion::Content => {
            app.focus_region = FocusRegion::Tabs;
        }
        FocusRegion::Tabs => {
            logout(paths, app).await?;
        }
    }
    Ok(())
}

async fn handle_logged_in_enter(paths: &ShellPaths, app: &mut App) -> Result<()> {
    match app.focus_region {
        FocusRegion::Tabs => {
            app.focus_region = FocusRegion::Content;
        }
        FocusRegion::Content => match app.logged_in_tab {
            LoggedInTab::Dashboard => {
                app.status_line = "Use Left and Right to switch tabs.".to_string();
            }
            LoggedInTab::Permissions => {
                if let Err(err) = cycle_selected_policy(paths, app).await {
                    app.status_line = err.to_string();
                }
            }
            LoggedInTab::Settings => {
                let action = SettingsAction::all()[app.settings_cursor];
                if let Err(err) = run_settings_action(paths, app, action).await {
                    app.status_line = err.to_string();
                }
            }
        },
        FocusRegion::Actions => {
            let action = PermissionsAction::all()[app.action_cursor];
            if let Err(err) = run_permissions_action(paths, app, action).await {
                app.status_line = err.to_string();
            }
        }
    }
    Ok(())
}

async fn handle_input_modal_key(paths: &ShellPaths, app: &mut App, code: KeyCode) -> Result<()> {
    let Some(modal) = app.input_modal.as_mut() else {
        return Ok(());
    };
    match code {
        KeyCode::Esc => {
            app.input_modal = None;
            app.status_line = "Input cancelled.".to_string();
        }
        KeyCode::Backspace => {
            modal.input.pop();
        }
        KeyCode::Enter => {
            let value = modal.input.clone();
            let target = modal.target.clone();
            if value.trim().is_empty() {
                modal.error = Some("Input cannot be empty.".to_string());
                return Ok(());
            }
            commit_input_value(paths, app, target, value).await?;
            app.input_modal = None;
        }
        KeyCode::Char(c) => {
            modal.input.push(c);
            modal.error = None;
        }
        _ => {}
    }
    Ok(())
}

async fn commit_input_value(
    _paths: &ShellPaths,
    app: &mut App,
    target: InputTarget,
    value: String,
) -> Result<()> {
    match target {
        InputTarget::UnlockSecret => {
            let profile = selected_profile(app)?;
            activate_profile_with_secret(_paths, app, &profile.id, value).await?;
            return Ok(());
        }
        InputTarget::OnboardPackageInput => app.onboard_connect.package_input = value,
        InputTarget::OnboardSecret => app.onboard_connect.onboarding_secret = value,
        InputTarget::OnboardLabel => app.onboard_save.label = value,
        InputTarget::OnboardVaultSecret => app.onboard_save.vault_secret = value,
        InputTarget::OnboardVaultConfirm => app.onboard_save.vault_confirm = value,
        InputTarget::ImportPackageInput => app.import_connect.package_input = value,
        InputTarget::ImportSecret => app.import_connect.package_secret = value,
        InputTarget::ImportLabel => app.import_save.label = value,
        InputTarget::ImportVaultSecret => app.import_save.vault_secret = value,
        InputTarget::ImportVaultConfirm => app.import_save.vault_confirm = value,
        InputTarget::RecoverPackageInput => app.recover_connect.package_input = value,
        InputTarget::RecoverSecret => app.recover_connect.package_secret = value,
        InputTarget::RecoverLabel => app.recover_save.label = value,
        InputTarget::RecoverVaultSecret => app.recover_save.vault_secret = value,
        InputTarget::RecoverVaultConfirm => app.recover_save.vault_confirm = value,
        InputTarget::GenerateKeysetName => app.generate_config.keyset_name = value,
        InputTarget::GenerateThreshold => app.generate_config.threshold = value,
        InputTarget::GenerateCount => app.generate_config.count = value,
        InputTarget::GenerateLocalLabel => {
            if let Some(state) = app.generate_profile.as_mut() {
                state.label = value;
            }
        }
        InputTarget::GenerateRelayUrls => {
            if let Some(state) = app.generate_profile.as_mut() {
                state.relay_urls = value;
            }
        }
        InputTarget::GenerateVaultSecret => {
            if let Some(state) = app.generate_profile.as_mut() {
                state.vault_secret = value;
            }
        }
        InputTarget::GenerateVaultConfirm => {
            if let Some(state) = app.generate_profile.as_mut() {
                state.vault_confirm = value;
            }
        }
        InputTarget::GenerateDistributionSecret => {
            if let Some(state) = app.generate_profile.as_mut() {
                state.distribution_secret = value;
            }
        }
    }
    app.status_line = "Input saved.".to_string();
    Ok(())
}

async fn refresh(paths: &ShellPaths, app: &mut App) -> Result<()> {
    app.profiles = list_profiles(paths)?;
    if let Some(preferred_profile_id) = &app.preferred_profile_id
        && let Some(position) = app
            .profiles
            .iter()
            .position(|profile| &profile.id == preferred_profile_id)
    {
        app.profile_cursor = position;
    } else if app.profile_cursor >= app.profiles.len() && !app.profiles.is_empty() {
        app.profile_cursor = app.profiles.len() - 1;
    }

    app.active_profile = match &app.active_profile_id {
        Some(profile_id) => Some(read_profile(paths, profile_id)?),
        None => None,
    };
    app.daemon_running = app
        .active_profile
        .as_ref()
        .map(|profile| read_daemon_metadata(paths, &profile.id).is_ok())
        .unwrap_or(false);

    app.snapshot = None;
    app.log_lines.clear();
    if let Some(profile) = &app.active_profile {
        let log_path = daemon_log_path(paths, &profile.id);
        app.log_lines = read_log_lines(&log_path, app.logs_verbose).unwrap_or_default();
    }
    if let Some(profile) = &app.active_profile
        && app.daemon_running
    {
        let runtime = daemon_runtime_query(paths, &profile.id, ControlCommand::RuntimeStatus).await;
        if let Ok(runtime) = runtime {
            let runtime: RuntimeStatusView = serde_json::from_value(runtime)?;
            app.snapshot = Some(DaemonSnapshot { runtime });
        }
    }
    app.last_refresh_at = Some(now_unix_secs());
    clamp_cursors(app);
    Ok(())
}

async fn prepare_initial_state(paths: &ShellPaths, app: &mut App) -> Result<()> {
    if app.profiles.is_empty() {
        app.mode = AppMode::LoggedOut;
        app.logged_out_view = LoggedOutView::Home;
        app.focus_region = FocusRegion::Actions;
        return Ok(());
    }

    if let Some(profile_id) = app.preferred_profile_id.clone()
        && let Some(passphrase) = app.session_vault_secrets.get(&profile_id).cloned()
    {
        activate_profile_with_secret(paths, app, &profile_id, passphrase).await?;
        return Ok(());
    }

    if let Some(profile_id) = &app.preferred_profile_id
        && let Some(position) = app
            .profiles
            .iter()
            .position(|profile| &profile.id == profile_id)
    {
        app.profile_cursor = position;
        open_input_modal(
            app,
            InputTarget::UnlockSecret,
            "Unlock Profile",
            "Type the vault secret for the selected profile to log in and start the daemon.",
            String::new(),
            true,
        );
    }
    app.mode = AppMode::LoggedOut;
    app.logged_out_view = LoggedOutView::Home;
    app.focus_region = FocusRegion::Content;
    Ok(())
}

fn open_home_action(app: &mut App, action: HomeAction) {
    app.row_cursor = 0;
    app.focus_region = FocusRegion::Content;
    app.status_line = action.description().to_string();
    app.logged_out_view = match action {
        HomeAction::OnboardPackage => LoggedOutView::OnboardConnect,
        HomeAction::ImportExisting => LoggedOutView::ImportConnect,
        HomeAction::RecoverShare => LoggedOutView::RecoverConnect,
        HomeAction::GenerateKeyset => LoggedOutView::GenerateConfig,
    };
}

fn return_to_home(app: &mut App) {
    app.logged_out_view = LoggedOutView::Home;
    app.focus_region = if app.profiles.is_empty() {
        FocusRegion::Actions
    } else {
        FocusRegion::Content
    };
    app.row_cursor = 0;
}

fn selected_profile(app: &App) -> Result<ProfileManifest> {
    if app.profiles.is_empty() {
        bail!("No profiles found yet. Use onboarding or keyset generation first.");
    }
    app.profiles
        .get(app.profile_cursor)
        .cloned()
        .ok_or_else(|| anyhow!("invalid profile selection"))
}

async fn activate_profile_with_secret(
    paths: &ShellPaths,
    app: &mut App,
    profile_id: &str,
    passphrase: String,
) -> Result<()> {
    validate_profile_unlock_with_passphrase(paths, profile_id, Some(passphrase.clone()))?;
    app.session_vault_secrets
        .insert(profile_id.to_string(), passphrase.clone());
    if read_daemon_metadata(paths, profile_id).is_err() {
        let _ = start_profile_daemon_with_passphrase(paths, profile_id, Some(passphrase)).await?;
    }
    app.active_profile_id = Some(profile_id.to_string());
    app.preferred_profile_id = Some(profile_id.to_string());
    app.mode = AppMode::LoggedIn;
    app.logged_in_tab = LoggedInTab::Dashboard;
    app.logged_out_view = LoggedOutView::Home;
    app.focus_region = FocusRegion::Tabs;
    app.input_modal = None;
    app.status_line = format!("Logged into {profile_id}.");
    refresh(paths, app).await
}

async fn logout(paths: &ShellPaths, app: &mut App) -> Result<()> {
    if let Some(profile_id) = app.active_profile_id.clone() {
        if read_daemon_metadata(paths, &profile_id).is_ok() {
            let _ = stop_profile_daemon(paths, &profile_id).await;
        }
        app.session_vault_secrets.remove(&profile_id);
    }
    app.active_profile_id = None;
    app.active_profile = None;
    app.snapshot = None;
    app.daemon_running = false;
    app.status_line = "Logged out and stopped the signer daemon.".to_string();
    app.should_quit = true;
    Ok(())
}

async fn connect_onboarding(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let package = resolve_text_or_path(&app.onboard_connect.package_input)?;
    let connected =
        connect_onboarding_package_preview(&package, app.onboard_connect.onboarding_secret.clone())
            .await?;
    app.onboard_save.connection = Some(connected.clone());
    app.onboard_save.label = connected.preview.label.clone();
    app.onboard_save.vault_secret.clear();
    app.onboard_save.vault_confirm.clear();
    app.logged_out_view = LoggedOutView::OnboardSave;
    app.row_cursor = 0;
    app.status_line = "Onboarding package connected. Review and save this device.".to_string();
    let _ = paths;
    Ok(())
}

async fn save_onboarded_profile(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(connection) = app.onboard_save.connection.clone() else {
        bail!("connect an onboarding package first");
    };
    ensure_matching_secret(
        &app.onboard_save.vault_secret,
        &app.onboard_save.vault_confirm,
        "vault secret",
    )?;
    let label = app.onboard_save.label.trim().to_string();
    if label.is_empty() {
        bail!("profile name is required");
    }
    let import = finalize_connected_onboarding_import(
        paths,
        connection,
        Some(label),
        None,
        Some(app.onboard_save.vault_secret.clone()),
    )?;
    let profile_id = profile_id_from_import(&import)?;
    let secret = app.onboard_save.vault_secret.clone();
    app.onboard_save = OnboardSaveState::default();
    refresh(paths, app).await?;
    activate_profile_with_secret(paths, app, &profile_id, secret).await
}

fn connect_bfprofile_import(app: &mut App) -> Result<()> {
    let package = resolve_text_or_path(&app.import_connect.package_input)?;
    let (preview, payload) =
        preview_bfprofile_value(&package, app.import_connect.package_secret.clone(), None)?;
    app.import_save.preview = Some(preview.clone());
    app.import_save.payload = Some(payload);
    app.import_save.label = preview.label.clone();
    app.import_save.vault_secret.clear();
    app.import_save.vault_confirm.clear();
    app.logged_out_view = LoggedOutView::ImportSave;
    app.row_cursor = 0;
    app.status_line = "Profile package decoded. Review and save this device.".to_string();
    Ok(())
}

async fn save_imported_profile(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(payload) = app.import_save.payload.clone() else {
        bail!("load a bfprofile package first");
    };
    ensure_matching_secret(
        &app.import_save.vault_secret,
        &app.import_save.vault_confirm,
        "vault secret",
    )?;
    let label = app.import_save.label.trim().to_string();
    if label.is_empty() {
        bail!("profile name is required");
    }
    let import = import_profile_from_bfprofile_payload(
        paths,
        payload,
        Some(label),
        None,
        Some(app.import_save.vault_secret.clone()),
    )?;
    let profile_id = profile_id_from_import(&import)?;
    let secret = app.import_save.vault_secret.clone();
    app.import_save = PendingImportState::default();
    refresh(paths, app).await?;
    activate_profile_with_secret(paths, app, &profile_id, secret).await
}

async fn connect_bfshare_recovery(app: &mut App) -> Result<()> {
    let package = resolve_text_or_path(&app.recover_connect.package_input)?;
    let (preview, payload) =
        preview_bfshare_recovery(&package, app.recover_connect.package_secret.clone(), None)
            .await?;
    app.recover_save.preview = Some(preview.clone());
    app.recover_save.payload = Some(payload);
    app.recover_save.label = preview.label.clone();
    app.recover_save.vault_secret.clear();
    app.recover_save.vault_confirm.clear();
    app.logged_out_view = LoggedOutView::RecoverSave;
    app.row_cursor = 0;
    app.status_line = "Recovery package resolved. Review and save this device.".to_string();
    Ok(())
}

async fn save_recovered_profile(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(payload) = app.recover_save.payload.clone() else {
        bail!("load a recovery package first");
    };
    ensure_matching_secret(
        &app.recover_save.vault_secret,
        &app.recover_save.vault_confirm,
        "vault secret",
    )?;
    let label = app.recover_save.label.trim().to_string();
    if label.is_empty() {
        bail!("profile name is required");
    }
    let import = import_profile_from_bfprofile_payload(
        paths,
        payload,
        Some(label),
        None,
        Some(app.recover_save.vault_secret.clone()),
    )?;
    let profile_id = profile_id_from_import(&import)?;
    let secret = app.recover_save.vault_secret.clone();
    app.recover_save = PendingImportState::default();
    refresh(paths, app).await?;
    activate_profile_with_secret(paths, app, &profile_id, secret).await
}

fn create_generate_draft(app: &mut App) -> Result<()> {
    let keyset_name = app.generate_config.keyset_name.trim().to_string();
    if keyset_name.is_empty() {
        bail!("keyset name is required");
    }
    let threshold = app
        .generate_config
        .threshold
        .trim()
        .parse::<u16>()
        .map_err(|_| anyhow!("threshold must be a positive integer"))?;
    let count = app
        .generate_config
        .count
        .trim()
        .parse::<u16>()
        .map_err(|_| anyhow!("member count must be a positive integer"))?;
    let draft = create_generated_keyset_draft(keyset_name, threshold, count)?;
    let label = draft
        .shares
        .first()
        .map(|share| share.label.clone())
        .unwrap_or_else(|| "Device 1".to_string());
    app.generate_profile = Some(GenerateProfileState {
        draft,
        share_cursor: 0,
        label,
        relay_urls: String::new(),
        vault_secret: String::new(),
        vault_confirm: String::new(),
        distribution_secret: String::new(),
    });
    app.logged_out_view = LoggedOutView::GenerateProfile;
    app.row_cursor = 0;
    app.status_line = "Keyset created. Choose the local share and save this device.".to_string();
    Ok(())
}

fn cycle_generated_share(app: &mut App) {
    let Some(state) = app.generate_profile.as_mut() else {
        return;
    };
    if state.draft.shares.is_empty() {
        return;
    }
    state.share_cursor = (state.share_cursor + 1) % state.draft.shares.len();
    state.label = state.draft.shares[state.share_cursor].label.clone();
}

async fn save_generated_profile(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(state) = app.generate_profile.clone() else {
        bail!("generate a keyset first");
    };
    ensure_matching_secret(&state.vault_secret, &state.vault_confirm, "vault secret")?;
    if state.distribution_secret.trim().is_empty() {
        bail!("onboarding secret is required for the remaining shares");
    }
    let relays = parse_relays(&state.relay_urls)?;
    let selected_share = state
        .draft
        .shares
        .get(state.share_cursor)
        .cloned()
        .ok_or_else(|| anyhow!("select a local share first"))?;
    let import = import_generated_share(
        paths,
        &state.draft,
        selected_share.member_idx,
        state.label.trim().to_string(),
        relays.clone(),
        Some(state.vault_secret.clone()),
    )?;
    let profile = manifest_from_import(&import)?;
    let export_root = paths
        .state_dir
        .join("generated-onboarding")
        .join(&profile.id);
    fs::create_dir_all(&export_root)
        .map_err(|error| anyhow!("create {}: {error}", export_root.display()))?;
    let mut packages = Vec::new();
    for share in &state.draft.shares {
        if share.member_idx == selected_share.member_idx {
            continue;
        }
        let package_text = export_generated_onboarding_package(
            &state.draft,
            share.member_idx,
            relays.clone(),
            selected_share.share_public_key.clone(),
            state.distribution_secret.clone(),
        )?;
        let path = export_root.join(format!("member-{}.bfonboard.txt", share.member_idx));
        fs::write(&path, &package_text)
            .map_err(|error| anyhow!("write {}: {error}", path.display()))?;
        packages.push(GeneratedPackageView {
            member_idx: share.member_idx,
            label: share.label.clone(),
            path: path.display().to_string(),
            package_text,
        });
    }
    let secret = state.vault_secret.clone();
    app.generate_distribute = Some(GenerateDistributeState {
        profile: profile.clone(),
        vault_secret: secret,
        packages,
        cursor: 0,
    });
    app.generate_profile = None;
    app.logged_out_view = LoggedOutView::GenerateDistribute;
    app.row_cursor = 0;
    app.status_line = format!(
        "Saved {} and exported onboarding packages for the remaining shares.",
        profile.id
    );
    refresh(paths, app).await
}

async fn cycle_selected_policy(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = &app.active_profile else {
        bail!("select a profile first");
    };
    let field = PolicyField::all()[app.permission_field_cursor];
    if app.row_cursor == 0 {
        let document = parse_policy_document(&profile.policy_overrides)?;
        let current = document.default_override.unwrap_or_default();
        let next = next_policy_value(policy_value(&current, field));
        let _ = set_profile_default_policy_override(
            paths,
            &profile.id,
            field.direction(),
            field.method(),
            next,
        )?;
        app.status_line = format!(
            "Default {} set to {}. Restart daemon to apply default changes.",
            field.short_label(),
            policy_value_label(next)
        );
    } else {
        let peers = policy_rows(app);
        let Some((pubkey, current, _)) = peers.get(app.row_cursor.saturating_sub(1)).cloned()
        else {
            return Ok(());
        };
        let next = next_policy_value(policy_value(&current, field));
        let (_manifest, effective_override) = set_profile_peer_policy_override(
            paths,
            &profile.id,
            &pubkey,
            field.direction(),
            field.method(),
            next,
        )?;
        if app.daemon_running {
            let _ = daemon_runtime_query(
                paths,
                &profile.id,
                ControlCommand::SetPolicyOverride {
                    peer: pubkey.clone(),
                    policy_override_json: serde_json::to_string(&effective_override)?,
                },
            )
            .await?;
        }
        app.status_line = format!(
            "{} {} set to {}.",
            shorten(&pubkey),
            field.short_label(),
            policy_value_label(next)
        );
    }
    refresh(paths, app).await
}

async fn run_permissions_action(
    paths: &ShellPaths,
    app: &mut App,
    action: PermissionsAction,
) -> Result<()> {
    match action {
        PermissionsAction::NextField => {
            app.permission_field_cursor =
                (app.permission_field_cursor + 1) % PolicyField::all().len();
            app.status_line = format!(
                "Editing {} overrides.",
                PolicyField::all()[app.permission_field_cursor].short_label()
            );
            Ok(())
        }
        PermissionsAction::CyclePolicy => cycle_selected_policy(paths, app).await,
        PermissionsAction::ClearOverride => clear_selected_policy(paths, app).await,
        PermissionsAction::PingPeer => ping_selected_peer(paths, app).await,
        PermissionsAction::OnboardPeer => onboard_selected_peer(paths, app).await,
        PermissionsAction::Refresh => refresh(paths, app).await,
    }
}

async fn run_settings_action(
    paths: &ShellPaths,
    app: &mut App,
    action: SettingsAction,
) -> Result<()> {
    match action {
        SettingsAction::Refresh => refresh(paths, app).await,
        SettingsAction::StartStopDaemon => toggle_daemon(paths, app).await,
        SettingsAction::ToggleLogDetail => {
            app.logs_verbose = !app.logs_verbose;
            refresh(paths, app).await?;
            app.status_line = if app.logs_verbose {
                "Expanded daemon log detail.".to_string()
            } else {
                "Collapsed daemon log detail.".to_string()
            };
            Ok(())
        }
        SettingsAction::Logout => logout(paths, app).await,
    }
}

async fn toggle_daemon(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = app.active_profile.clone() else {
        bail!("no active profile");
    };
    if app.daemon_running {
        let _ = stop_profile_daemon(paths, &profile.id).await?;
        app.status_line = format!("Stopped daemon for {}.", profile.label);
    } else {
        let Some(secret) = app.session_vault_secrets.get(&profile.id).cloned() else {
            bail!("unlock the profile again to start its daemon");
        };
        let _ = start_profile_daemon_with_passphrase(paths, &profile.id, Some(secret)).await?;
        app.status_line = format!("Started daemon for {}.", profile.label);
    }
    refresh(paths, app).await
}

async fn ping_selected_peer(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some((profile_id, peer_pubkey)) = selected_peer_pubkey(app) else {
        bail!("select a peer first");
    };
    let result = daemon_runtime_query(
        paths,
        &profile_id,
        ControlCommand::Ping {
            peer: peer_pubkey.clone(),
            timeout_secs: None,
        },
    )
    .await?;
    app.status_line = format!(
        "Pinged {} ({})",
        shorten(&peer_pubkey),
        result
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown-request")
    );
    refresh(paths, app).await
}

async fn onboard_selected_peer(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some((profile_id, peer_pubkey)) = selected_peer_pubkey(app) else {
        bail!("select a peer first");
    };
    let result = daemon_runtime_query(
        paths,
        &profile_id,
        ControlCommand::Onboard {
            peer: peer_pubkey.clone(),
            timeout_secs: None,
        },
    )
    .await?;
    app.status_line = format!(
        "Onboarded with {} ({})",
        shorten(&peer_pubkey),
        result
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown-request")
    );
    refresh(paths, app).await
}

async fn clear_selected_policy(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = &app.active_profile else {
        bail!("no active profile");
    };
    let field = PolicyField::all()[app.permission_field_cursor];
    if app.row_cursor == 0 {
        let _ = set_profile_default_policy_override(
            paths,
            &profile.id,
            field.direction(),
            field.method(),
            PolicyOverrideValue::Unset,
        )?;
        app.status_line = format!(
            "Default {} override cleared. Restart daemon to apply default changes.",
            field.short_label()
        );
        return refresh(paths, app).await;
    }
    let rows = policy_rows(app);
    let Some((pubkey, current, is_override)) = rows.get(app.row_cursor.saturating_sub(1)).cloned()
    else {
        bail!("select a peer row first");
    };
    if !is_override && policy_value(&current, field) == PolicyOverrideValue::Unset {
        bail!("selected peer field is already inheriting the default override");
    }
    let (_manifest, effective) = set_profile_peer_policy_override(
        paths,
        &profile.id,
        &pubkey,
        field.direction(),
        field.method(),
        PolicyOverrideValue::Unset,
    )?;
    if app.daemon_running {
        let _ = daemon_runtime_query(
            paths,
            &profile.id,
            ControlCommand::SetPolicyOverride {
                peer: pubkey.clone(),
                policy_override_json: serde_json::to_string(&effective)?,
            },
        )
        .await?;
    }
    app.status_line = format!(
        "Cleared {} override for {}.",
        field.short_label(),
        shorten(&pubkey)
    );
    refresh(paths, app).await
}

fn selected_peer_pubkey(app: &App) -> Option<(String, String)> {
    if app.row_cursor == 0 {
        return None;
    }
    let profile_id = app.active_profile_id.clone()?;
    let peer_pubkey = policy_rows(app)
        .get(app.row_cursor.saturating_sub(1))?
        .0
        .clone();
    Some((profile_id, peer_pubkey))
}

fn next_tab(app: &mut App) {
    let tabs = LoggedInTab::all();
    let index = tabs
        .iter()
        .position(|tab| *tab == app.logged_in_tab)
        .unwrap_or(0);
    app.logged_in_tab = tabs[(index + 1) % tabs.len()];
    app.row_cursor = 0;
    app.action_cursor = 0;
    app.settings_cursor = 0;
}

fn prev_tab(app: &mut App) {
    let tabs = LoggedInTab::all();
    let index = tabs
        .iter()
        .position(|tab| *tab == app.logged_in_tab)
        .unwrap_or(0);
    app.logged_in_tab = if index == 0 {
        tabs[tabs.len() - 1]
    } else {
        tabs[index - 1]
    };
    app.row_cursor = 0;
    app.action_cursor = 0;
    app.settings_cursor = 0;
}

fn clamp_cursors(app: &mut App) {
    if app.profile_cursor >= app.profiles.len() && !app.profiles.is_empty() {
        app.profile_cursor = app.profiles.len() - 1;
    }
    let permission_rows = permission_row_count(app);
    if app.row_cursor >= permission_rows {
        app.row_cursor = permission_rows - 1;
    }
    app.action_cursor = app
        .action_cursor
        .min(PermissionsAction::all().len().saturating_sub(1));
    app.settings_cursor = app
        .settings_cursor
        .min(SettingsAction::all().len().saturating_sub(1));
    app.home_action_cursor = app
        .home_action_cursor
        .min(HomeAction::all().len().saturating_sub(1));
}

fn render(frame: &mut ratatui::Frame<'_>, app: &App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    match app.mode {
        AppMode::LoggedOut => {
            render_logged_out_header(frame, areas[0], app);
            render_logged_out_body(frame, areas[1], app);
        }
        AppMode::LoggedIn => {
            render_logged_in_tabs(frame, areas[0], app);
            render_logged_in_body(frame, areas[1], app);
        }
    }

    let footer = Paragraph::new(Text::from(vec![
        Line::from(app.status_line.as_str()),
        Line::from("Arrows move | Enter select | Esc back | q quit"),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(footer, areas[2]);

    if let Some(modal) = &app.input_modal {
        render_input_modal(frame, areas[1], modal);
    }
}

fn render_logged_out_header(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let title = match app.logged_out_view {
        LoggedOutView::Home => "igloo-shell :: Home",
        LoggedOutView::OnboardConnect | LoggedOutView::OnboardSave => {
            "igloo-shell :: Onboard Package"
        }
        LoggedOutView::ImportConnect | LoggedOutView::ImportSave => {
            "igloo-shell :: Import Existing"
        }
        LoggedOutView::RecoverConnect | LoggedOutView::RecoverSave => {
            "igloo-shell :: Recover Share"
        }
        LoggedOutView::GenerateConfig
        | LoggedOutView::GenerateProfile
        | LoggedOutView::GenerateDistribute => "igloo-shell :: Generate Keyset",
    };
    let widget =
        Paragraph::new(title).block(Block::default().title("Logged Out").borders(Borders::ALL));
    frame.render_widget(widget, area);
}

fn render_logged_in_tabs(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let titles = LoggedInTab::all()
        .iter()
        .map(|tab| Line::from(Span::raw(tab.title())))
        .collect::<Vec<_>>();
    let selected = LoggedInTab::all()
        .iter()
        .position(|tab| *tab == app.logged_in_tab)
        .unwrap_or(0);
    let profile_title = app
        .active_profile
        .as_ref()
        .map(|profile| format!("{} ({})", profile.label, short_profile_id(&profile.id)))
        .unwrap_or_else(|| "No Profile".to_string());
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(focus_block(
            format!("igloo-shell profile load :: {profile_title}"),
            app.focus_region == FocusRegion::Tabs,
        ))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn render_logged_out_body(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    match app.logged_out_view {
        LoggedOutView::Home => render_home(frame, area, app),
        LoggedOutView::OnboardConnect => render_onboard_connect(frame, area, app),
        LoggedOutView::OnboardSave => render_onboard_save(frame, area, app),
        LoggedOutView::ImportConnect => render_import_connect(frame, area, app),
        LoggedOutView::ImportSave => render_import_save(frame, area, app),
        LoggedOutView::RecoverConnect => render_recover_connect(frame, area, app),
        LoggedOutView::RecoverSave => render_recover_save(frame, area, app),
        LoggedOutView::GenerateConfig => render_generate_config(frame, area, app),
        LoggedOutView::GenerateProfile => render_generate_profile(frame, area, app),
        LoggedOutView::GenerateDistribute => render_generate_distribute(frame, area, app),
    }
}

fn render_logged_in_body(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    match app.logged_in_tab {
        LoggedInTab::Dashboard => render_dashboard(frame, area, app),
        LoggedInTab::Permissions => render_permissions(frame, area, app),
        LoggedInTab::Settings => render_settings(frame, area, app),
    }
}

fn render_home(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(36),
            Constraint::Min(24),
            Constraint::Length(34),
        ])
        .split(area);

    let profile_items = if app.profiles.is_empty() {
        vec![ListItem::new("No local profiles yet")]
    } else {
        app.profiles
            .iter()
            .map(|profile| {
                let mut label = format!("{} ({})", profile.label, short_profile_id(&profile.id));
                if app.session_vault_secrets.contains_key(&profile.id) {
                    label.push_str(" [unlocked]");
                }
                if read_daemon_status_hint(app, &profile.id) {
                    label.push_str(" [running]");
                }
                ListItem::new(label)
            })
            .collect()
    };
    let profiles = List::new(profile_items)
        .block(focus_block(
            "Profiles",
            app.focus_region == FocusRegion::Content,
        ))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    let mut state = ListState::default().with_selected(Some(app.profile_cursor));
    frame.render_stateful_widget(profiles, chunks[0], &mut state);

    let mut detail_lines = vec![
        Line::from("Select an existing profile to unlock it,"),
        Line::from("or choose one of the onboarding paths."),
        Line::from(""),
    ];
    if let Some(profile) = app.profiles.get(app.profile_cursor) {
        detail_lines.push(Line::from(format!("Name: {}", profile.label)));
        detail_lines.push(Line::from(format!(
            "Profile Id: {} ({})",
            short_profile_id(&profile.id),
            profile.id
        )));
        detail_lines.push(Line::from(format!(
            "Relay profile: {}",
            profile.relay_profile
        )));
        detail_lines.push(Line::from(format!("Created: {}", profile.created_at)));
        detail_lines.push(Line::from(format!(
            "Status: {}",
            if app.session_vault_secrets.contains_key(&profile.id) {
                "unlocked"
            } else {
                "locked"
            }
        )));
    } else {
        detail_lines.push(Line::from("No profile selected."));
    }
    detail_lines.push(Line::from(""));
    detail_lines.push(Line::from("Enter on a profile opens the vault prompt."));
    let details = Paragraph::new(Text::from(detail_lines))
        .block(Block::default().title("Welcome").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(details, chunks[1]);

    let actions = HomeAction::all()
        .iter()
        .map(|action| ListItem::new(action.title()))
        .collect::<Vec<_>>();
    let action_list = List::new(actions)
        .block(focus_block(
            "Onboarding Paths",
            app.focus_region == FocusRegion::Actions,
        ))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    let mut action_state = ListState::default().with_selected(Some(app.home_action_cursor));
    frame.render_stateful_widget(action_list, chunks[2], &mut action_state);
}

fn render_form_rows(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    title: &str,
    description: &str,
    rows: Vec<Row<'static>>,
    selected: usize,
) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(10)])
        .split(area);
    let intro = Paragraph::new(Text::from(vec![
        Line::from(title.to_string()),
        Line::from(""),
        Line::from(description.to_string()),
    ]))
    .block(Block::default().title("Flow").borders(Borders::ALL))
    .wrap(Wrap { trim: true });
    frame.render_widget(intro, sections[0]);

    let table = Table::new(rows, [Constraint::Length(22), Constraint::Min(20)])
        .header(Row::new(vec!["Field", "Value"]).style(Style::default().fg(Color::Yellow)))
        .block(focus_block("Fields", true))
        .row_highlight_style(Style::default().bg(Color::Blue))
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);
    let mut state = TableState::default().with_selected(Some(selected));
    frame.render_stateful_widget(table, sections[1], &mut state);
}

fn render_onboard_connect(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    render_form_rows(
        frame,
        area,
        "Connect With bfonboard",
        "Step 1 of 2. Paste a bfonboard package or provide a local file path, then enter the onboarding secret to complete the handshake.",
        vec![
            form_row(
                "Package",
                display_value(&app.onboard_connect.package_input, false),
            ),
            form_row(
                "Onboarding secret",
                display_value(&app.onboard_connect.onboarding_secret, true),
            ),
            action_row(
                "Connect",
                "Complete the onboarding handshake and preview the resulting device.",
            ),
            action_row("Back", "Return to Home."),
        ],
        app.row_cursor,
    );
}

fn render_onboard_save(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let preview = app
        .onboard_save
        .connection
        .as_ref()
        .map(|entry| &entry.preview);
    let mut rows = vec![
        form_row(
            "Profile name",
            display_value(&app.onboard_save.label, false),
        ),
        form_row(
            "Vault secret",
            display_value(&app.onboard_save.vault_secret, true),
        ),
        form_row(
            "Confirm secret",
            display_value(&app.onboard_save.vault_confirm, true),
        ),
        action_row(
            "Save profile",
            "Import this device locally, start the daemon, and enter the dashboard.",
        ),
        action_row("Back", "Return to the onboarding connect step."),
    ];
    if let Some(preview) = preview {
        rows.insert(
            0,
            form_row(
                "Preview",
                format!(
                    "{} · threshold {} of {} · {}",
                    shorten(&preview.group_public_key),
                    preview.threshold,
                    preview.total_count,
                    shorten(&preview.share_public_key)
                ),
            ),
        );
    }
    render_form_rows(
        frame,
        area,
        "Save Onboarded Device",
        "Step 2 of 2. Confirm the device details, then choose the local profile name and vault secret for this machine.",
        rows,
        app.row_cursor,
    );
}

fn render_import_connect(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    render_form_rows(
        frame,
        area,
        "Import bfprofile",
        "Paste a bfprofile package or provide a local file path, then enter the package secret to preview the profile.",
        vec![
            form_row(
                "bfprofile",
                display_value(&app.import_connect.package_input, false),
            ),
            form_row(
                "Package secret",
                display_value(&app.import_connect.package_secret, true),
            ),
            action_row(
                "Load preview",
                "Decode the profile package and review its details.",
            ),
            action_row("Back", "Return to Home."),
        ],
        app.row_cursor,
    );
}

fn render_import_save(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let preview = app.import_save.preview.as_ref();
    let mut rows = Vec::new();
    if let Some(preview) = preview {
        rows.push(form_row(
            "Preview",
            format!(
                "{} · threshold {} of {} · {}",
                shorten(&preview.group_public_key),
                preview.threshold,
                preview.total_count,
                shorten(&preview.share_public_key)
            ),
        ));
    }
    rows.extend([
        form_row("Profile name", display_value(&app.import_save.label, false)),
        form_row(
            "Vault secret",
            display_value(&app.import_save.vault_secret, true),
        ),
        form_row(
            "Confirm secret",
            display_value(&app.import_save.vault_confirm, true),
        ),
        action_row(
            "Import profile",
            "Save the imported profile locally, start the daemon, and enter the dashboard.",
        ),
        action_row("Back", "Return to the import step."),
    ]);
    render_form_rows(
        frame,
        area,
        "Save Imported Profile",
        "Confirm the decoded profile details, then choose the local profile name and vault secret for this machine.",
        rows,
        app.row_cursor,
    );
}

fn render_recover_connect(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    render_form_rows(
        frame,
        area,
        "Recover From bfshare",
        "Paste a bfshare package or provide a local file path, then enter the share secret to resolve the published backup and preview this device.",
        vec![
            form_row(
                "bfshare",
                display_value(&app.recover_connect.package_input, false),
            ),
            form_row(
                "Share secret",
                display_value(&app.recover_connect.package_secret, true),
            ),
            action_row(
                "Load preview",
                "Resolve the backup and review the recovered profile.",
            ),
            action_row("Back", "Return to Home."),
        ],
        app.row_cursor,
    );
}

fn render_recover_save(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let preview = app.recover_save.preview.as_ref();
    let mut rows = Vec::new();
    if let Some(preview) = preview {
        rows.push(form_row(
            "Preview",
            format!(
                "{} · threshold {} of {} · {}",
                shorten(&preview.group_public_key),
                preview.threshold,
                preview.total_count,
                shorten(&preview.share_public_key)
            ),
        ));
    }
    rows.extend([
        form_row(
            "Profile name",
            display_value(&app.recover_save.label, false),
        ),
        form_row(
            "Vault secret",
            display_value(&app.recover_save.vault_secret, true),
        ),
        form_row(
            "Confirm secret",
            display_value(&app.recover_save.vault_confirm, true),
        ),
        action_row(
            "Recover profile",
            "Save the recovered profile locally, start the daemon, and enter the dashboard.",
        ),
        action_row("Back", "Return to the recovery step."),
    ]);
    render_form_rows(
        frame,
        area,
        "Save Recovered Device",
        "Confirm the recovered profile details, then choose the local profile name and vault secret for this machine.",
        rows,
        app.row_cursor,
    );
}

fn render_generate_config(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    render_form_rows(
        frame,
        area,
        "Generate Keyset",
        "Step 1 of 3. Create the keyset that will be split across devices.",
        vec![
            form_row(
                "Keyset name",
                display_value(&app.generate_config.keyset_name, false),
            ),
            form_row(
                "Threshold",
                display_value(&app.generate_config.threshold, false),
            ),
            form_row(
                "Member count",
                display_value(&app.generate_config.count, false),
            ),
            action_row(
                "Generate",
                "Create the keyset and move to local device setup.",
            ),
            action_row("Back", "Return to Home."),
        ],
        app.row_cursor,
    );
}

fn render_generate_profile(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let Some(state) = &app.generate_profile else {
        return;
    };
    let selected_share = state
        .draft
        .shares
        .get(state.share_cursor)
        .map(|share| format!("{} ({})", share.label, share.member_idx))
        .unwrap_or_else(|| "No share selected".to_string());
    render_form_rows(
        frame,
        area,
        "Save Local Generated Device",
        "Step 2 of 3. Choose which share belongs on this machine, then set the relay URLs, local vault secret, and a shared onboarding secret for the remaining packages.",
        vec![
            form_row("Local share", selected_share),
            form_row("Profile name", display_value(&state.label, false)),
            form_row("Relay URLs", display_value(&state.relay_urls, false)),
            form_row("Vault secret", display_value(&state.vault_secret, true)),
            form_row("Confirm secret", display_value(&state.vault_confirm, true)),
            form_row(
                "Onboarding secret",
                display_value(&state.distribution_secret, true),
            ),
            action_row(
                "Save local profile",
                "Import the selected share locally and export onboarding packages for the remaining shares.",
            ),
            action_row("Back", "Return to the keyset configuration step."),
        ],
        app.row_cursor,
    );
}

fn render_generate_distribute(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let Some(state) = &app.generate_distribute else {
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(36), Constraint::Min(24)])
        .split(area);
    let items = state
        .packages
        .iter()
        .map(|package| ListItem::new(format!("{} ({})", package.label, package.member_idx)))
        .chain(std::iter::once(ListItem::new("Open Dashboard")))
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(focus_block("Generated Packages", true))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    let mut list_state = ListState::default().with_selected(Some(state.cursor));
    frame.render_stateful_widget(list, chunks[0], &mut list_state);

    let lines = if let Some(package) = state.packages.get(state.cursor) {
        vec![
            Line::from(format!("Saved: {}", package.path)),
            Line::from(""),
            Line::from("Package preview:"),
            Line::from(package.package_text.clone()),
        ]
    } else {
        vec![
            Line::from(format!(
                "Local profile {} is ready. The remaining onboarding packages were saved to disk.",
                state.profile.id
            )),
            Line::from(""),
            Line::from("Select Open Dashboard to enter the logged-in shell."),
        ]
    };
    let detail = Paragraph::new(Text::from(lines))
        .block(Block::default().title("Distribution").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, chunks[1]);
}

fn render_dashboard(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let text = if let Some(snapshot) = &app.snapshot {
        let mut lines = vec![
            Line::from(format!(
                "Profile: {}",
                app.active_profile
                    .as_ref()
                    .map(|profile| profile.label.as_str())
                    .unwrap_or("-")
            )),
            Line::from(format!("Daemon running: {}", yes_no(app.daemon_running))),
            Line::from(format!(
                "Share pk: {}  Group pk: {}",
                shorten(&snapshot.runtime.metadata.share_public_key),
                shorten(&snapshot.runtime.metadata.group_public_key)
            )),
            Line::from(format!(
                "Threshold: {} of {}",
                snapshot.runtime.readiness.threshold,
                snapshot.runtime.metadata.peers.len() + 1
            )),
            Line::from(format!(
                "Runtime ready: {}  restore: {}  sign: {}  ecdh: {}",
                yes_no(snapshot.runtime.readiness.runtime_ready),
                yes_no(snapshot.runtime.readiness.restore_complete),
                yes_no(snapshot.runtime.readiness.sign_ready),
                yes_no(snapshot.runtime.readiness.ecdh_ready),
            )),
            Line::from(format!(
                "Known peers: {}  Pending ops: {}  Last refresh: {}",
                snapshot.runtime.status.known_peers,
                snapshot.runtime.pending_operations.len(),
                format_unix(app.last_refresh_at),
            )),
            Line::from(""),
            Line::from("Pending operations:"),
        ];
        if snapshot.runtime.pending_operations.is_empty() {
            lines.push(Line::from("  none"));
        } else {
            lines.extend(
                snapshot
                    .runtime
                    .pending_operations
                    .iter()
                    .take(8)
                    .map(|op| {
                        Line::from(format!(
                            "  {} {} peers={} threshold={}",
                            op.op_type,
                            shorten(&op.request_id),
                            op.target_peers.len(),
                            op.threshold
                        ))
                    }),
            );
        }
        Text::from(lines)
    } else if app.active_profile.is_some() {
        Text::from(vec![
            Line::from(format!(
                "Profile: {}",
                app.active_profile
                    .as_ref()
                    .map(|profile| profile.label.as_str())
                    .unwrap_or("-")
            )),
            Line::from(format!("Daemon running: {}", yes_no(app.daemon_running))),
            Line::from("No live runtime snapshot is available yet."),
            Line::from("Use Settings to refresh or start the daemon."),
        ])
    } else {
        Text::from(vec![
            Line::from("No active profile."),
            Line::from("Use Logout to stop the daemon and return to the terminal."),
        ])
    };
    let widget = Paragraph::new(text)
        .block(focus_block(
            "Dashboard",
            app.focus_region == FocusRegion::Content,
        ))
        .wrap(Wrap { trim: true });
    frame.render_widget(widget, area);
}

fn render_permissions(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(28)])
        .split(area);
    let side_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(12)])
        .split(chunks[1]);
    let mut rows = Vec::new();
    let selected_field = PolicyField::all()[app.permission_field_cursor];
    let default_policy = app
        .active_profile
        .as_ref()
        .and_then(|profile| parse_policy_document(&profile.policy_overrides).ok())
        .and_then(|doc| doc.default_override)
        .unwrap_or_default();
    rows.push(Row::new(vec![
        Cell::from("default"),
        Cell::from("default policy"),
        Cell::from("-"),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RequestPing,
        ))),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RequestOnboard,
        ))),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RequestSign,
        ))),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RequestEcdh,
        ))),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RespondPing,
        ))),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RespondOnboard,
        ))),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RespondSign,
        ))),
        Cell::from(policy_value_label(policy_value(
            &default_policy,
            PolicyField::RespondEcdh,
        ))),
    ]));
    for (pubkey, policy, is_override) in policy_rows(app) {
        let online = app
            .snapshot
            .as_ref()
            .and_then(|snapshot| {
                snapshot
                    .runtime
                    .peers
                    .iter()
                    .find(|peer| peer.pubkey == pubkey)
            })
            .map(|peer| yes_no(peer.online).to_string())
            .unwrap_or_else(|| "-".to_string());
        rows.push(Row::new(vec![
            Cell::from(if is_override { "override" } else { "default" }),
            Cell::from(shorten(&pubkey)),
            Cell::from(online),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RequestPing,
            ))),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RequestOnboard,
            ))),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RequestSign,
            ))),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RequestEcdh,
            ))),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RespondPing,
            ))),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RespondOnboard,
            ))),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RespondSign,
            ))),
            Cell::from(policy_value_label(policy_value(
                &policy,
                PolicyField::RespondEcdh,
            ))),
        ]));
    }
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec![
            "source", "peer", "online", "rq.ping", "rq.onbd", "rq.sign", "rq.ecdh", "rs.ping",
            "rs.onbd", "rs.sign", "rs.ecdh",
        ])
        .style(Style::default().fg(Color::Yellow)),
    )
    .block(focus_block(
        format!("Permissions · editing {}", selected_field.short_label()),
        app.focus_region == FocusRegion::Content,
    ))
    .row_highlight_style(Style::default().bg(Color::Blue))
    .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);
    let mut state = TableState::default().with_selected(Some(app.row_cursor));
    frame.render_stateful_widget(table, chunks[0], &mut state);

    let actions = PermissionsAction::all()
        .iter()
        .map(|action| {
            let label = match action {
                PermissionsAction::NextField => {
                    format!("{} ({})", action.title(), selected_field.short_label())
                }
                _ => action.title().to_string(),
            };
            ListItem::new(label)
        })
        .collect::<Vec<_>>();
    let list = List::new(actions)
        .block(focus_block(
            "Actions",
            app.focus_region == FocusRegion::Actions,
        ))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    let mut action_state = ListState::default().with_selected(Some(app.action_cursor));
    frame.render_stateful_widget(list, side_chunks[0], &mut action_state);

    let detail = selected_permission_detail(app);
    let detail_lines = match detail {
        Some(detail) => vec![
            Line::from(format!("Peer: {}", shorten(&detail.pubkey))),
            Line::from(format!(
                "Manual rq.sign/rs.sign: {}/{}",
                policy_value_label(detail.manual_override.request.sign),
                policy_value_label(detail.manual_override.respond.sign)
            )),
            Line::from(format!(
                "Effective rq.sign/rs.sign: {}/{}",
                yes_no(detail.effective_policy.request.sign),
                yes_no(detail.effective_policy.respond.sign)
            )),
            Line::from(format!(
                "Effective rq.onbd/rs.onbd: {}/{}",
                yes_no(detail.effective_policy.request.onboard),
                yes_no(detail.effective_policy.respond.onboard)
            )),
            Line::from(format!(
                "Effective rq.ecdh/rs.ecdh: {}/{}",
                yes_no(detail.effective_policy.request.ecdh),
                yes_no(detail.effective_policy.respond.ecdh)
            )),
            Line::from(format!(
                "Remote observed: {}",
                detail
                    .remote_observation
                    .as_ref()
                    .map(|_| "yes")
                    .unwrap_or("no")
            )),
            Line::from(
                detail
                    .remote_observation
                    .as_ref()
                    .map(|remote| format!("Observed at: {}", remote.updated))
                    .unwrap_or_else(|| "Observed at: -".to_string()),
            ),
            Line::from(
                detail
                    .remote_observation
                    .as_ref()
                    .map(|remote| format!("Observation rev: {}", remote.revision))
                    .unwrap_or_else(|| "Observation rev: -".to_string()),
            ),
            Line::from(
                detail
                    .remote_observation
                    .as_ref()
                    .map(|remote| {
                        format!(
                            "Remote rq.ping/rs.ping: {}/{}",
                            yes_no(remote.request.ping),
                            yes_no(remote.respond.ping)
                        )
                    })
                    .unwrap_or_else(|| "Remote rq.ping/rs.ping: -/-".to_string()),
            ),
            Line::from(
                detail
                    .remote_observation
                    .as_ref()
                    .map(|remote| {
                        format!(
                            "Remote rq.onbd/rs.onbd: {}/{}",
                            yes_no(remote.request.onboard),
                            yes_no(remote.respond.onboard)
                        )
                    })
                    .unwrap_or_else(|| "Remote rq.onbd/rs.onbd: -/-".to_string()),
            ),
            Line::from(
                detail
                    .remote_observation
                    .as_ref()
                    .map(|remote| {
                        format!(
                            "Remote rs.sign/rs.ecdh: {}/{}",
                            yes_no(remote.respond.sign),
                            yes_no(remote.respond.ecdh)
                        )
                    })
                    .unwrap_or_else(|| "Remote rs.sign/rs.ecdh: -/-".to_string()),
            ),
        ],
        None => vec![
            Line::from("Select a peer row to inspect"),
            Line::from("local override, remote observation,"),
            Line::from("and effective runtime policy."),
        ],
    };
    let detail_widget = Paragraph::new(Text::from(detail_lines))
        .block(
            Block::default()
                .title("Runtime Detail")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail_widget, side_chunks[1]);
}

fn render_settings(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(28)])
        .split(area);
    let actions = SettingsAction::all()
        .iter()
        .map(|action| {
            let label = match action {
                SettingsAction::Refresh => "Refresh",
                SettingsAction::StartStopDaemon => {
                    if app.daemon_running {
                        "Stop Daemon"
                    } else {
                        "Start Daemon"
                    }
                }
                SettingsAction::ToggleLogDetail => {
                    if app.logs_verbose {
                        "Compact Logs"
                    } else {
                        "Verbose Logs"
                    }
                }
                SettingsAction::Logout => "Logout",
            };
            ListItem::new(label)
        })
        .collect::<Vec<_>>();
    let list = List::new(actions)
        .block(focus_block(
            "Settings",
            app.focus_region == FocusRegion::Content,
        ))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    let mut state = ListState::default().with_selected(Some(app.settings_cursor));
    frame.render_stateful_widget(list, chunks[0], &mut state);

    let mut lines = vec![
        Line::from(format!("Daemon running: {}", yes_no(app.daemon_running))),
        Line::from(format!(
            "Relay profile: {}",
            app.active_profile
                .as_ref()
                .map(|profile| profile.relay_profile.as_str())
                .unwrap_or("-")
        )),
        Line::from(format!(
            "Last export: {}",
            app.last_export_path.as_deref().unwrap_or("-")
        )),
        Line::from(""),
        Line::from("Logs:"),
    ];
    if app.log_lines.is_empty() {
        lines.push(Line::from("  No log file available"));
    } else {
        lines.extend(
            app.log_lines
                .iter()
                .take(if app.logs_verbose {
                    app.log_lines.len()
                } else {
                    LOG_TAIL_LINES
                })
                .map(|line| Line::from(format!("  {line}"))),
        );
    }
    let detail = Paragraph::new(Text::from(lines))
        .block(Block::default().title("Details").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, chunks[1]);
}

fn render_input_modal(frame: &mut ratatui::Frame<'_>, area: Rect, modal: &InputModal) {
    let popup = centered_rect(72, 34, area);
    frame.render_widget(Clear, popup);
    let mut lines = vec![
        Line::from(modal.description.clone()),
        Line::from(""),
        Line::from(format!(
            "Input: {}",
            if modal.secret {
                "*".repeat(modal.input.len())
            } else {
                modal.input.clone()
            }
        )),
        Line::from(""),
        Line::from("Enter submits. Esc cancels."),
    ];
    if let Some(error) = &modal.error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Error: {error}")));
    }
    let widget = Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .title(modal.title.clone())
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(widget, popup);
}

fn read_daemon_status_hint(app: &App, profile_id: &str) -> bool {
    app.active_profile_id.as_deref() == Some(profile_id) && app.daemon_running
}

fn form_row(label: &str, value: String) -> Row<'static> {
    Row::new(vec![Cell::from(label.to_string()), Cell::from(value)])
}

fn action_row(label: &str, description: &str) -> Row<'static> {
    Row::new(vec![
        Cell::from(label.to_string()),
        Cell::from(description.to_string()),
    ])
}

fn open_input_modal(
    app: &mut App,
    target: InputTarget,
    title: &str,
    description: &str,
    current_value: String,
    secret: bool,
) {
    app.input_modal = Some(InputModal {
        title: title.to_string(),
        description: description.to_string(),
        target,
        input: current_value,
        secret,
        error: None,
    });
}

fn profile_id_from_import(import: &ProfileImportResult) -> Result<String> {
    match import {
        ProfileImportResult::ProfileCreated { profile, .. } => Ok(profile.id.clone()),
        ProfileImportResult::OnboardingStaged { .. } => {
            bail!("unexpected staged onboarding import")
        }
    }
}

fn manifest_from_import(import: &ProfileImportResult) -> Result<ProfileManifest> {
    match import {
        ProfileImportResult::ProfileCreated { profile, .. } => Ok(profile.clone()),
        ProfileImportResult::OnboardingStaged { .. } => {
            bail!("unexpected staged onboarding import")
        }
    }
}

fn ensure_matching_secret(secret: &str, confirm: &str, label: &str) -> Result<()> {
    if secret.trim().is_empty() {
        bail!("{label} is required");
    }
    if secret != confirm {
        bail!("{label} confirmation does not match");
    }
    Ok(())
}

fn resolve_text_or_path(value: &str) -> Result<String> {
    let candidate = value.trim();
    if candidate.is_empty() {
        bail!("input is required");
    }
    if Path::new(candidate).exists() {
        return fs::read_to_string(candidate)
            .map_err(|error| anyhow!("read {candidate}: {error}"))
            .map(|text| text.trim().to_string());
    }
    Ok(candidate.to_string())
}

fn parse_relays(value: &str) -> Result<Vec<String>> {
    let relays = value
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if relays.is_empty() {
        bail!("at least one relay url is required");
    }
    Ok(relays)
}

fn display_value(value: &str, secret: bool) -> String {
    if value.trim().is_empty() {
        "Enter a value".to_string()
    } else if secret {
        "*".repeat(value.len())
    } else {
        value.to_string()
    }
}

fn focus_block<'a, T>(title: T, focused: bool) -> Block<'a>
where
    T: Into<ratatui::text::Line<'a>>,
{
    let mut block = Block::default().title(title).borders(Borders::ALL);
    if focused {
        block = block.border_style(Style::default().fg(Color::Cyan));
    }
    block
}

fn parse_policy_document(value: &serde_json::Value) -> Result<PolicyOverridesDocument> {
    if value.is_null() {
        return Ok(PolicyOverridesDocument {
            default_override: None,
            peer_overrides: Vec::new(),
        });
    }
    serde_json::from_value(value.clone()).context("parse policy overrides document")
}

fn policy_rows(app: &App) -> Vec<(String, PeerPolicyOverride, bool)> {
    let mut rows = Vec::new();
    let document = app
        .active_profile
        .as_ref()
        .and_then(|profile| parse_policy_document(&profile.policy_overrides).ok())
        .unwrap_or(PolicyOverridesDocument {
            default_override: None,
            peer_overrides: Vec::new(),
        });
    let default_policy = document.default_override.clone().unwrap_or_default();
    let overrides = document
        .peer_overrides
        .into_iter()
        .map(|entry| (entry.pubkey, entry.policy_override))
        .collect::<BTreeMap<_, _>>();
    let runtime_permission_states = app
        .snapshot
        .as_ref()
        .map(|snapshot| {
            snapshot
                .runtime
                .peer_permission_states
                .iter()
                .map(|entry| (entry.pubkey.clone(), entry.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let peers = permission_peer_pubkeys(app);
    for peer in peers {
        let runtime_state = runtime_permission_states.get(&peer);
        let runtime_has_effective_restrictions = runtime_state.is_some_and(|entry| {
            !method_policy_view_allows_all(&entry.effective_policy.request)
                || !method_policy_view_allows_all(&entry.effective_policy.respond)
        });
        if let Some(policy) = overrides
            .get(&peer)
            .cloned()
            .or_else(|| runtime_state.map(|entry| entry.manual_override.clone()))
        {
            rows.push((peer, policy, true));
        } else {
            rows.push((
                peer,
                default_policy.clone(),
                runtime_has_effective_restrictions,
            ));
        }
    }
    for (peer, policy) in overrides {
        if rows.iter().any(|(existing, _, _)| existing == &peer) {
            continue;
        }
        rows.push((peer, policy, true));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

fn selected_permission_detail(app: &App) -> Option<&PeerPermissionStateView> {
    if app.row_cursor == 0 {
        return None;
    }
    let pubkey = policy_rows(app)
        .get(app.row_cursor.saturating_sub(1))?
        .0
        .clone();
    app.snapshot
        .as_ref()?
        .runtime
        .peer_permission_states
        .iter()
        .find(|entry| entry.pubkey == pubkey)
}

fn method_policy_view_allows_all(policy: &MethodPolicyView) -> bool {
    policy.ping && policy.onboard && policy.sign && policy.ecdh
}

fn permission_peer_pubkeys(app: &App) -> Vec<String> {
    let mut peers = BTreeMap::<String, ()>::new();
    if let Some(snapshot) = &app.snapshot {
        for peer in &snapshot.runtime.metadata.peers {
            peers.insert(peer.clone(), ());
        }
        for peer in &snapshot.runtime.peers {
            peers.insert(peer.pubkey.clone(), ());
        }
    }
    if let Some(profile) = &app.active_profile
        && let Ok(document) = parse_policy_document(&profile.policy_overrides)
    {
        for entry in document.peer_overrides {
            peers.insert(entry.pubkey, ());
        }
    }
    peers.into_keys().collect()
}

fn permission_row_count(app: &App) -> usize {
    (policy_rows(app).len() + 1).max(1)
}

fn policy_value(policy: &PeerPolicyOverride, field: PolicyField) -> PolicyOverrideValue {
    match field {
        PolicyField::RequestPing => policy.request.ping,
        PolicyField::RequestOnboard => policy.request.onboard,
        PolicyField::RequestSign => policy.request.sign,
        PolicyField::RequestEcdh => policy.request.ecdh,
        PolicyField::RespondPing => policy.respond.ping,
        PolicyField::RespondOnboard => policy.respond.onboard,
        PolicyField::RespondSign => policy.respond.sign,
        PolicyField::RespondEcdh => policy.respond.ecdh,
    }
}

fn next_policy_value(value: PolicyOverrideValue) -> PolicyOverrideValue {
    match value {
        PolicyOverrideValue::Unset => PolicyOverrideValue::Allow,
        PolicyOverrideValue::Allow => PolicyOverrideValue::Deny,
        PolicyOverrideValue::Deny => PolicyOverrideValue::Unset,
    }
}

fn policy_value_label(value: PolicyOverrideValue) -> &'static str {
    match value {
        PolicyOverrideValue::Unset => "unset",
        PolicyOverrideValue::Allow => "allow",
        PolicyOverrideValue::Deny => "deny",
    }
}

fn read_log_lines(path: &Path, verbose: bool) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)?;
    let mut lines = raw.lines().map(|line| line.to_string()).collect::<Vec<_>>();
    if !verbose && lines.len() > LOG_TAIL_LINES {
        lines = lines.split_off(lines.len() - LOG_TAIL_LINES);
    }
    Ok(lines)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn shorten(value: &str) -> String {
    if value.len() <= 12 {
        value.to_string()
    } else {
        format!("{}..{}", &value[..6], &value[value.len() - 4..])
    }
}

fn format_unix(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn short_profile_id(profile_id: &str) -> &str {
    &profile_id[..profile_id.len().min(8)]
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    use crate::shell::ProfileManifest;

    fn sample_profile(id: &str, label: &str) -> ProfileManifest {
        ProfileManifest {
            id: id.to_string(),
            label: label.to_string(),
            group_ref: "group.json".to_string(),
            share_ref: format!("vault-{id}"),
            relay_profile: "local".to_string(),
            runtime_options: Value::Null,
            policy_overrides: Value::Null,
            remote_policy_observations: Value::Null,
            state_path: format!("/tmp/{id}.state"),
            daemon_socket_path: format!("/tmp/{id}.sock"),
            created_at: 1,
            last_used_at: Some(1),
        }
    }

    #[test]
    fn home_starts_logged_out_and_selects_profiles() {
        let mut app = App::new(TuiLaunchOptions::default());
        app.profiles = vec![
            sample_profile("alpha", "Alpha"),
            sample_profile("beta", "Beta"),
        ];
        assert_eq!(app.mode, AppMode::LoggedOut);
        assert_eq!(app.logged_out_view, LoggedOutView::Home);
        assert_eq!(
            selected_profile(&app).expect("selected profile").id,
            "alpha"
        );
    }

    #[test]
    fn home_action_switches_view() {
        let mut app = App::new(TuiLaunchOptions::default());
        open_home_action(&mut app, HomeAction::GenerateKeyset);
        assert_eq!(app.logged_out_view, LoggedOutView::GenerateConfig);
        open_home_action(&mut app, HomeAction::ImportExisting);
        assert_eq!(app.logged_out_view, LoggedOutView::ImportConnect);
    }

    #[test]
    fn generate_draft_parses_numeric_fields() {
        let mut app = App::new(TuiLaunchOptions::default());
        app.generate_config.keyset_name = "Alpha".to_string();
        app.generate_config.threshold = "2".to_string();
        app.generate_config.count = "3".to_string();
        create_generate_draft(&mut app).expect("create draft");
        let state = app.generate_profile.expect("generate profile state");
        assert_eq!(state.draft.keyset_name, "Alpha");
        assert_eq!(state.draft.threshold, 2);
        assert_eq!(state.draft.count, 3);
    }

    #[test]
    fn parse_relays_accepts_commas_and_spaces() {
        let relays = parse_relays("ws://one, ws://two ws://three").expect("parse relays");
        assert_eq!(relays, vec!["ws://one", "ws://two", "ws://three"]);
    }

    #[test]
    fn matching_secret_requires_confirmation() {
        let error =
            ensure_matching_secret("alpha", "beta", "vault secret").expect_err("expected mismatch");
        assert!(error.to_string().contains("confirmation"));
    }

    #[test]
    fn permission_rows_include_runtime_peers_even_without_metadata_peer_list() {
        let mut app = App::new(TuiLaunchOptions::default());
        let mut profile = sample_profile("alpha", "Alpha");
        profile.policy_overrides = serde_json::json!([]);
        app.active_profile = Some(profile);
        app.snapshot = Some(DaemonSnapshot {
            runtime: RuntimeStatusView {
                status: DeviceStatusView {
                    device_id: "alpha".to_string(),
                    pending_ops: 0,
                    last_active: 0,
                    known_peers: 2,
                    request_seq: 0,
                },
                metadata: RuntimeMetadataView {
                    device_id: "alpha".to_string(),
                    member_idx: 1,
                    share_public_key: "share".to_string(),
                    group_public_key: "group".to_string(),
                    peers: Vec::new(),
                },
                readiness: RuntimeReadinessView {
                    runtime_ready: true,
                    restore_complete: true,
                    sign_ready: true,
                    ecdh_ready: true,
                    threshold: 2,
                    signing_peer_count: 2,
                    ecdh_peer_count: 2,
                    last_refresh_at: Some(1),
                    degraded_reasons: Vec::new(),
                },
                peer_permission_states: Vec::new(),
                peers: vec![
                    PeerStatusView {
                        idx: 2,
                        pubkey: "peer-b".to_string(),
                        known: true,
                        last_seen: Some(1),
                        online: true,
                        incoming_available: 1,
                        outgoing_available: 1,
                        outgoing_spent: 0,
                        can_sign: true,
                        should_send_nonces: true,
                    },
                    PeerStatusView {
                        idx: 3,
                        pubkey: "peer-a".to_string(),
                        known: true,
                        last_seen: Some(1),
                        online: false,
                        incoming_available: 0,
                        outgoing_available: 0,
                        outgoing_spent: 0,
                        can_sign: false,
                        should_send_nonces: false,
                    },
                ],
                pending_operations: Vec::new(),
            },
        });

        let rows = policy_rows(&app);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "peer-a");
        assert_eq!(rows[1].0, "peer-b");
        assert_eq!(permission_row_count(&app), 3);
    }

    #[test]
    fn selected_peer_pubkey_skips_default_policy_row() {
        let mut app = App::new(TuiLaunchOptions::default());
        let mut profile = sample_profile("alpha", "Alpha");
        profile.policy_overrides = serde_json::json!([]);
        app.active_profile_id = Some("alpha".to_string());
        app.active_profile = Some(profile);
        app.snapshot = Some(DaemonSnapshot {
            runtime: RuntimeStatusView {
                status: DeviceStatusView {
                    device_id: "alpha".to_string(),
                    pending_ops: 0,
                    last_active: 0,
                    known_peers: 1,
                    request_seq: 0,
                },
                metadata: RuntimeMetadataView {
                    device_id: "alpha".to_string(),
                    member_idx: 1,
                    share_public_key: "share".to_string(),
                    group_public_key: "group".to_string(),
                    peers: vec!["peer-a".to_string()],
                },
                readiness: RuntimeReadinessView {
                    runtime_ready: true,
                    restore_complete: true,
                    sign_ready: true,
                    ecdh_ready: true,
                    threshold: 2,
                    signing_peer_count: 1,
                    ecdh_peer_count: 1,
                    last_refresh_at: Some(1),
                    degraded_reasons: Vec::new(),
                },
                peer_permission_states: Vec::new(),
                peers: vec![PeerStatusView {
                    idx: 2,
                    pubkey: "peer-a".to_string(),
                    known: true,
                    last_seen: Some(1),
                    online: true,
                    incoming_available: 1,
                    outgoing_available: 1,
                    outgoing_spent: 0,
                    can_sign: true,
                    should_send_nonces: true,
                }],
                pending_operations: Vec::new(),
            },
        });

        app.row_cursor = 0;
        assert!(selected_peer_pubkey(&app).is_none());

        app.row_cursor = 1;
        assert_eq!(
            selected_peer_pubkey(&app).expect("selected peer"),
            ("alpha".to_string(), "peer-a".to_string())
        );
    }

    #[test]
    fn logged_in_dashboard_up_moves_focus_to_tabs() {
        let mut app = App::new(TuiLaunchOptions::default());
        app.mode = AppMode::LoggedIn;
        app.logged_in_tab = LoggedInTab::Dashboard;
        app.focus_region = FocusRegion::Content;

        handle_logged_in_up(&mut app);

        assert_eq!(app.focus_region, FocusRegion::Tabs);
    }

    #[test]
    fn logged_in_content_left_does_not_jump_to_tabs() {
        let mut app = App::new(TuiLaunchOptions::default());
        app.mode = AppMode::LoggedIn;
        app.logged_in_tab = LoggedInTab::Dashboard;
        app.focus_region = FocusRegion::Content;

        handle_logged_in_left(&mut app, KeyModifiers::empty());

        assert_eq!(app.focus_region, FocusRegion::Content);
    }
}
