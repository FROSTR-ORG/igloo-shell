use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use bifrost_app::host::ControlCommand;
use bifrost_core::types::PeerPolicy;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
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
    ProfileManifest, ShellPaths, clear_profile_peer_policy, daemon_log_path, daemon_runtime_query,
    export_profile, list_profiles, read_daemon_metadata, read_profile, set_profile_default_policy,
    set_profile_peer_policy, start_profile_daemon, stop_profile_daemon,
};

const INVITE_EXPIRY_SECS: u64 = 3600;
const LOG_TAIL_LINES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Overview,
    Peers,
    Invites,
    Policies,
    Logs,
    Setup,
}

impl Screen {
    fn all() -> [Screen; 6] {
        [
            Screen::Overview,
            Screen::Peers,
            Screen::Invites,
            Screen::Policies,
            Screen::Logs,
            Screen::Setup,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            Screen::Overview => "Overview",
            Screen::Peers => "Peers",
            Screen::Invites => "Invites",
            Screen::Policies => "Policies",
            Screen::Logs => "Logs",
            Screen::Setup => "Setup",
        }
    }
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
    pending_operations: Vec<PendingOperationView>,
}

#[derive(Debug, Clone, Deserialize)]
struct PendingInviteRecordView {
    challenge_hex: String,
    callback_peer_pubkey_hex: String,
    relays: Vec<String>,
    created_at: u64,
    expires_at: u64,
    consumed_at: Option<u64>,
    label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyOverridesDocument {
    #[serde(default)]
    default_policy: Option<PeerPolicy>,
    #[serde(default)]
    peer_overrides: Vec<PolicyPeerOverride>,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyPeerOverride {
    pubkey: String,
    policy: PeerPolicy,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct DaemonSnapshot {
    runtime: RuntimeStatusView,
    invites: Vec<PendingInviteRecordView>,
    policies: BTreeMap<String, PeerPolicy>,
}

struct App {
    active_screen: Screen,
    profiles: Vec<ProfileManifest>,
    profile_cursor: usize,
    row_cursor: usize,
    active_profile_id: Option<String>,
    active_profile: Option<ProfileManifest>,
    snapshot: Option<DaemonSnapshot>,
    daemon_running: bool,
    status_line: String,
    last_refresh_at: Option<u64>,
    logs_verbose: bool,
    log_lines: Vec<String>,
    last_export_path: Option<String>,
    should_quit: bool,
}

impl App {
    fn new(profile_id: Option<String>) -> Self {
        Self {
            active_screen: Screen::Overview,
            profiles: Vec::new(),
            profile_cursor: 0,
            row_cursor: 0,
            active_profile_id: profile_id,
            active_profile: None,
            snapshot: None,
            daemon_running: false,
            status_line: "Tab switches sections. q quits.".to_string(),
            last_refresh_at: None,
            logs_verbose: false,
            log_lines: Vec::new(),
            last_export_path: None,
            should_quit: false,
        }
    }

    fn current_screen_index(&self) -> usize {
        Screen::all()
            .iter()
            .position(|screen| *screen == self.active_screen)
            .unwrap_or(0)
    }

    fn next_screen(&mut self) {
        let screens = Screen::all();
        let next = (self.current_screen_index() + 1) % screens.len();
        self.active_screen = screens[next];
        self.row_cursor = 0;
    }

    fn prev_screen(&mut self) {
        let screens = Screen::all();
        let next = if self.current_screen_index() == 0 {
            screens.len() - 1
        } else {
            self.current_screen_index() - 1
        };
        self.active_screen = screens[next];
        self.row_cursor = 0;
    }

    fn profile_title(&self) -> String {
        match &self.active_profile {
            Some(profile) => format!("{} ({})", profile.label, profile.id),
            None => "No Profile".to_string(),
        }
    }
}

pub async fn run_tui(paths: &ShellPaths, profile: Option<String>) -> Result<()> {
    let mut app = App::new(profile);
    refresh(paths, &mut app).await?;

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
    match code {
        KeyCode::Char('q') => {
            app.should_quit = true;
        }
        KeyCode::Tab => app.next_screen(),
        KeyCode::BackTab => app.prev_screen(),
        KeyCode::Left if modifiers.contains(KeyModifiers::SHIFT) => app.prev_screen(),
        KeyCode::Right if modifiers.contains(KeyModifiers::SHIFT) => app.next_screen(),
        KeyCode::Up => {
            if in_profile_selection(app) {
                app.profile_cursor = app.profile_cursor.saturating_sub(1);
            } else {
                app.row_cursor = app.row_cursor.saturating_sub(1);
            }
        }
        KeyCode::Down => {
            if in_profile_selection(app) {
                app.profile_cursor = app.profile_cursor.saturating_add(1);
            } else {
                app.row_cursor = app.row_cursor.saturating_add(1);
            }
        }
        KeyCode::Char('r') => refresh(paths, app).await?,
        KeyCode::Char('l') => {
            if app.active_screen == Screen::Logs {
                app.logs_verbose = !app.logs_verbose;
                app.status_line = if app.logs_verbose {
                    "Log detail expanded".to_string()
                } else {
                    "Log detail compact".to_string()
                };
            } else {
                app.active_screen = Screen::Logs;
                app.row_cursor = 0;
            }
        }
        KeyCode::Char('s') => toggle_daemon(paths, app).await?,
        KeyCode::Enter => {
            if app.active_profile.is_none() {
                attach_selected_profile(app)?;
                refresh(paths, app).await?;
            } else {
                match app.active_screen {
                    Screen::Peers => ping_selected_peer(paths, app).await?,
                    Screen::Invites => show_selected_invite(app),
                    Screen::Policies => cycle_selected_policy(paths, app).await?,
                    Screen::Setup => attach_selected_profile(app)?,
                    _ => {}
                }
            }
        }
        KeyCode::Char('p') if app.active_screen == Screen::Peers => ping_selected_peer(paths, app).await?,
        KeyCode::Char('o') if app.active_screen == Screen::Peers => onboard_selected_peer(paths, app).await?,
        KeyCode::Char('c') if app.active_screen == Screen::Invites => create_invite(paths, app).await?,
        KeyCode::Char('x') if app.active_screen == Screen::Invites => revoke_selected_invite(paths, app).await?,
        KeyCode::Char('x') if app.active_screen == Screen::Policies => clear_selected_policy(paths, app).await?,
        KeyCode::Char('e') if app.active_screen == Screen::Setup => export_selected_profile(paths, app)?,
        _ => {}
    }
    Ok(())
}

async fn refresh(paths: &ShellPaths, app: &mut App) -> Result<()> {
    app.profiles = list_profiles(paths)?;
    if app.active_profile_id.is_none() {
        if app.profiles.len() == 1 {
            app.active_profile_id = Some(app.profiles[0].id.clone());
        } else if app.profiles.is_empty() {
            app.active_screen = Screen::Setup;
        }
    }
    if app.profile_cursor >= app.profiles.len() && !app.profiles.is_empty() {
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
    if let Some(profile) = &app.active_profile
    {
        let log_path = daemon_log_path(paths, &profile.id);
        app.log_lines = read_log_lines(&log_path, app.logs_verbose).unwrap_or_default();
    }
    if let Some(profile) = &app.active_profile
        && app.daemon_running
    {
        let runtime: RuntimeStatusView = serde_json::from_value(
            daemon_runtime_query(paths, &profile.id, ControlCommand::RuntimeStatus).await?,
        )?;
        let invites: Vec<PendingInviteRecordView> = serde_json::from_value(
            daemon_runtime_query(paths, &profile.id, ControlCommand::InviteList).await?,
        )?;
        let policies: BTreeMap<String, PeerPolicy> = serde_json::from_value(
            daemon_runtime_query(paths, &profile.id, ControlCommand::Policies).await?,
        )?;
        app.snapshot = Some(DaemonSnapshot {
            runtime,
            invites,
            policies,
        });
    }
    app.last_refresh_at = Some(now_unix_secs());
    clamp_row_cursor(app);
    Ok(())
}

fn attach_selected_profile(app: &mut App) -> Result<()> {
    if app.profiles.is_empty() {
        app.status_line = "No profiles available. Use `igloo-shell setup`.".to_string();
        return Ok(());
    }
    let selected = app
        .profiles
        .get(app.profile_cursor)
        .ok_or_else(|| anyhow!("invalid profile selection"))?;
    app.active_profile_id = Some(selected.id.clone());
    app.active_profile = Some(selected.clone());
    app.status_line = format!("Attached to profile {}", selected.id);
    Ok(())
}

async fn toggle_daemon(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = app.active_profile.clone() else {
        app.status_line = "Select a profile first".to_string();
        return Ok(());
    };
    if app.daemon_running {
        let _ = stop_profile_daemon(paths, &profile.id).await?;
        app.status_line = format!("Stopped daemon for {}", profile.id);
    } else {
        let _ = start_profile_daemon(paths, &profile.id).await?;
        app.status_line = format!("Started daemon for {}", profile.id);
    }
    refresh(paths, app).await
}

async fn ping_selected_peer(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some((profile_id, peer)) = selected_peer(app) else {
        app.status_line = "No peer selected".to_string();
        return Ok(());
    };
    let result = daemon_runtime_query(
        paths,
        &profile_id,
        ControlCommand::Ping {
            peer: peer.pubkey.clone(),
            timeout_secs: None,
        },
    )
    .await?;
    app.status_line = format!(
        "Pinged {} ({})",
        shorten(&peer.pubkey),
        result
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown-request")
    );
    refresh(paths, app).await
}

async fn onboard_selected_peer(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some((profile_id, peer)) = selected_peer(app) else {
        app.status_line = "No peer selected".to_string();
        return Ok(());
    };
    let result = daemon_runtime_query(
        paths,
        &profile_id,
        ControlCommand::Onboard {
            peer: peer.pubkey.clone(),
            timeout_secs: None,
            challenge_hex32: None,
        },
    )
    .await?;
    app.status_line = format!(
        "Onboarded with {} ({})",
        shorten(&peer.pubkey),
        result
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown-request")
    );
    refresh(paths, app).await
}

async fn create_invite(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = &app.active_profile else {
        return Ok(());
    };
    let result = daemon_runtime_query(
        paths,
        &profile.id,
        ControlCommand::InviteCreate {
            relay_overrides: Vec::new(),
            expires_in_secs: INVITE_EXPIRY_SECS,
            label: None,
        },
    )
    .await?;
    let token = result
        .get("token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>");
    app.status_line = format!("Created invite: {token}");
    refresh(paths, app).await
}

fn show_selected_invite(app: &mut App) {
    if let Some(snapshot) = &app.snapshot
        && let Some(invite) = snapshot.invites.get(app.row_cursor)
    {
        app.status_line = format!(
            "Invite {} relays={} callback={}",
            invite.challenge_hex,
            invite.relays.join(","),
            shorten(&invite.callback_peer_pubkey_hex)
        );
    }
}

async fn revoke_selected_invite(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = &app.active_profile else {
        return Ok(());
    };
    let Some(snapshot) = &app.snapshot else {
        return Ok(());
    };
    let Some(invite) = snapshot.invites.get(app.row_cursor) else {
        app.status_line = "No invite selected".to_string();
        return Ok(());
    };
    let _ = daemon_runtime_query(
        paths,
        &profile.id,
        ControlCommand::InviteRevoke {
            challenge_hex32: invite.challenge_hex.clone(),
        },
    )
    .await?;
    app.status_line = format!("Revoked invite {}", invite.challenge_hex);
    refresh(paths, app).await
}

async fn cycle_selected_policy(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = &app.active_profile else {
        return Ok(());
    };
    let Some(manifest) = &app.active_profile else {
        return Ok(());
    };
        let document = parse_policy_document(&manifest.policy_overrides)?;
    if app.row_cursor == 0 {
        let next = next_policy(document.default_policy.unwrap_or_default());
        let _ = set_profile_default_policy(paths, &profile.id, next.clone())?;
        app.status_line = format!("Default policy set to {}", policy_mode_label(&next));
    } else {
        let peers = policy_rows(app);
        let Some((pubkey, current, _is_override)) = peers.get(app.row_cursor.saturating_sub(1)).cloned() else {
            return Ok(());
        };
        let next = next_policy(current);
        let _ = set_profile_peer_policy(paths, &profile.id, &pubkey, next.clone())?;
        if app.daemon_running {
            let _ = daemon_runtime_query(
                paths,
                &profile.id,
                ControlCommand::SetPolicy {
                    peer: pubkey.clone(),
                    send: next.request.sign,
                    receive: next.respond.sign,
                },
            )
            .await?;
        }
        app.status_line = format!("Peer {} policy set to {}", shorten(&pubkey), policy_mode_label(&next));
    }
    refresh(paths, app).await
}

async fn clear_selected_policy(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let Some(profile) = &app.active_profile else {
        return Ok(());
    };
    if app.row_cursor == 0 {
        app.status_line = "Default policy is cycled with Enter".to_string();
        return Ok(());
    }
    let rows = policy_rows(app);
    let Some((pubkey, _current, is_override)) = rows.get(app.row_cursor.saturating_sub(1)).cloned() else {
        return Ok(());
    };
    if !is_override {
        app.status_line = "Selected peer uses the default policy".to_string();
        return Ok(());
    }
    let (_manifest, effective) = clear_profile_peer_policy(paths, &profile.id, &pubkey)?;
    if app.daemon_running {
        let _ = daemon_runtime_query(
            paths,
            &profile.id,
            ControlCommand::SetPolicy {
                peer: pubkey.clone(),
                send: effective.request.sign,
                receive: effective.respond.sign,
            },
        )
        .await?;
    }
    app.status_line = format!("Cleared override for {}", shorten(&pubkey));
    refresh(paths, app).await
}

fn selected_peer(app: &App) -> Option<(String, PeerStatusView)> {
    let profile_id = app.active_profile_id.clone()?;
    let peer = app.snapshot.as_ref()?.runtime.peers.get(app.row_cursor)?.clone();
    Some((profile_id, peer))
}

fn clamp_row_cursor(app: &mut App) {
    if app.profile_cursor >= app.profiles.len() && !app.profiles.is_empty() {
        app.profile_cursor = app.profiles.len().saturating_sub(1);
    }
    let max = match app.active_screen {
        Screen::Peers => app.snapshot.as_ref().map(|s| s.runtime.peers.len()).unwrap_or(0),
        Screen::Invites => app.snapshot.as_ref().map(|s| s.invites.len()).unwrap_or(0),
        Screen::Policies => policy_rows(app).len() + 1,
        Screen::Setup => {
            if in_profile_selection(app) {
                app.profiles.len().max(1)
            } else {
                1
            }
        }
        _ => 1,
    };
    if max == 0 {
        app.row_cursor = 0;
    } else if app.row_cursor >= max {
        app.row_cursor = max.saturating_sub(1);
    }
}

fn render(frame: &mut ratatui::Frame<'_>, app: &App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let titles = Screen::all()
        .iter()
        .map(|screen| Line::from(Span::raw(screen.title())))
        .collect::<Vec<_>>();
    let tabs = Tabs::new(titles)
        .select(app.current_screen_index())
        .block(
            Block::default()
                .title(format!("igloo-shell tui :: {}", app.profile_title()))
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, areas[0]);

    match app.active_screen {
        Screen::Overview => render_overview(frame, areas[1], app),
        Screen::Peers => render_peers(frame, areas[1], app),
        Screen::Invites => render_invites(frame, areas[1], app),
        Screen::Policies => render_policies(frame, areas[1], app),
        Screen::Logs => render_logs(frame, areas[1], app),
        Screen::Setup => render_setup(frame, areas[1], app),
    }

    let footer = Paragraph::new(app.status_line.as_str())
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(footer, areas[2]);
}

fn render_overview(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let text = if let Some(snapshot) = &app.snapshot {
        let pending_lines = if snapshot.runtime.pending_operations.is_empty() {
            vec![Line::from("Pending operations: none")]
        } else {
            let mut lines = vec![Line::from("Pending operations:")];
            lines.extend(snapshot.runtime.pending_operations.iter().take(6).map(|op| {
                Line::from(format!(
                    "- {} {} peers={} threshold={} timeout={}",
                    op.op_type,
                    shorten(&op.request_id),
                    op.target_peers.len(),
                    op.threshold,
                    format_unix(Some(op.timeout_at)),
                ))
            }));
            lines
        };
        let mut lines = vec![
            Line::from(format!("Daemon running: {}", yes_no(app.daemon_running))),
            Line::from(format!("Device id: {}", snapshot.runtime.status.device_id)),
            Line::from(format!(
                "Share pk: {}  Group pk: {}",
                shorten(&snapshot.runtime.metadata.share_public_key),
                shorten(&snapshot.runtime.metadata.group_public_key)
            )),
            Line::from(format!(
                "Member idx: {}  group peers: {}  threshold: {}",
                snapshot.runtime.metadata.member_idx,
                snapshot.runtime.metadata.peers.len() + 1,
                snapshot.runtime.readiness.threshold + 1
            )),
            Line::from(format!(
                "Runtime ready: {}  restore: {}  sign: {}  ecdh: {}",
                yes_no(snapshot.runtime.readiness.runtime_ready),
                yes_no(snapshot.runtime.readiness.restore_complete),
                yes_no(snapshot.runtime.readiness.sign_ready),
                yes_no(snapshot.runtime.readiness.ecdh_ready),
            )),
            Line::from(format!(
                "Signing peers: {}  ECDH peers: {}  last peer refresh: {}",
                snapshot.runtime.readiness.signing_peer_count,
                snapshot.runtime.readiness.ecdh_peer_count,
                format_unix(snapshot.runtime.readiness.last_refresh_at),
            )),
            Line::from(format!(
                "Pending ops: {}  known peers: {}  request seq: {}  last active: {}",
                snapshot.runtime.status.pending_ops,
                snapshot.runtime.status.known_peers,
                snapshot.runtime.status.request_seq,
                format_unix(Some(snapshot.runtime.status.last_active)),
            )),
            Line::from(format!(
                "Degraded reasons: {}",
                if snapshot.runtime.readiness.degraded_reasons.is_empty() {
                    "none".to_string()
                } else {
                    snapshot.runtime.readiness.degraded_reasons.join(", ")
                }
            )),
            Line::from(format!("Last refresh: {}", format_unix(app.last_refresh_at))),
            Line::from(""),
        ];
        lines.extend(pending_lines);
        lines.push(Line::from(""));
        lines.push(Line::from("Actions: s start/stop daemon, r refresh, Tab switch screens"));
        Text::from(lines)
    } else if app.active_profile.is_some() {
        Text::from(vec![
            Line::from(format!("Daemon running: {}", yes_no(app.daemon_running))),
            Line::from("No live runtime snapshot available."),
            Line::from("Press s to start the daemon, then r to refresh."),
        ])
    } else {
        Text::from(vec![
            Line::from("No profile attached."),
            Line::from("Use Setup to select a profile."),
        ])
    };
    let widget = Paragraph::new(text)
        .block(Block::default().title("Overview").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(widget, area);
}

fn render_peers(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let rows = app
        .snapshot
        .as_ref()
        .map(|snapshot| {
            snapshot
                .runtime
                .peers
                .iter()
                .map(|peer| {
                    Row::new(vec![
                        Cell::from(peer.idx.to_string()),
                        Cell::from(shorten(&peer.pubkey)),
                        Cell::from(yes_no(peer.known)),
                        Cell::from(yes_no(peer.online)),
                        Cell::from(format_unix(peer.last_seen)),
                        Cell::from(peer.incoming_available.to_string()),
                        Cell::from(peer.outgoing_available.to_string()),
                        Cell::from(peer.outgoing_spent.to_string()),
                        Cell::from(yes_no(peer.can_sign)),
                        Cell::from(yes_no(peer.should_send_nonces)),
                    ])
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let widths = [
        Constraint::Length(4),
        Constraint::Length(14),
        Constraint::Length(5),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
    ];
    let table = Table::new(rows, widths)
        .header(Row::new(vec![
            "idx", "peer", "known", "online", "last seen", "in", "out", "spent", "sign", "nonce",
        ]).style(Style::default().fg(Color::Yellow)))
        .block(Block::default().title("Peers").borders(Borders::ALL))
        .row_highlight_style(Style::default().bg(Color::Blue))
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);
    let mut state = TableState::default().with_selected(Some(app.row_cursor));
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_invites(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let rows = app
        .snapshot
        .as_ref()
        .map(|snapshot| {
            snapshot
                .invites
                .iter()
                .map(|invite| {
                    Row::new(vec![
                        Cell::from(invite.label.clone().unwrap_or_else(|| "-".to_string())),
                        Cell::from(shorten(&invite.challenge_hex)),
                        Cell::from(invite.relays.len().to_string()),
                        Cell::from(format_unix(Some(invite.created_at))),
                        Cell::from(format_unix(Some(invite.expires_at))),
                        Cell::from(if invite.consumed_at.is_some() { "yes" } else { "no" }),
                        Cell::from(shorten(&invite.callback_peer_pubkey_hex)),
                    ])
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(14),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(14),
        ],
    )
    .header(
        Row::new(vec!["label", "challenge", "relays", "created", "expires", "used", "callback"])
            .style(Style::default().fg(Color::Yellow)),
    )
    .block(Block::default().title("Invites (c create, x revoke)").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::Blue))
    .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);
    let mut state = TableState::default().with_selected(Some(app.row_cursor));
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_policies(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let mut rows = Vec::new();
    let default_policy = app
        .active_profile
        .as_ref()
        .and_then(|profile| parse_policy_document(&profile.policy_overrides).ok())
        .and_then(|doc| doc.default_policy)
        .unwrap_or_default();
    rows.push(Row::new(vec![
        Cell::from("default"),
        Cell::from("all peers"),
        Cell::from(policy_mode_label(&default_policy)),
    ]));
    for (pubkey, policy, is_override) in policy_rows(app) {
        rows.push(Row::new(vec![
            Cell::from(if is_override { "override" } else { "default" }),
            Cell::from(shorten(&pubkey)),
            Cell::from(policy_mode_label(&policy)),
        ]));
    }
    let table = Table::new(
        rows,
        [Constraint::Length(10), Constraint::Length(16), Constraint::Length(14)],
    )
    .header(Row::new(vec!["source", "peer", "mode"]).style(Style::default().fg(Color::Yellow)))
    .block(Block::default().title("Policies (Enter cycles, x clears override)").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::Blue))
    .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);
    let mut state = TableState::default().with_selected(Some(app.row_cursor));
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_logs(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let lines = if app.log_lines.is_empty() {
        vec!["No log file available".to_string()]
    } else {
        app.log_lines.clone()
    };
    let widget = Paragraph::new(lines.join("\n"))
        .block(Block::default().title("Logs (l toggles detail)").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

fn render_setup(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(36), Constraint::Min(20)])
        .split(area);
    let items = if app.profiles.is_empty() {
        vec![ListItem::new("No profiles found")]
    } else {
        app.profiles
            .iter()
            .map(|profile| ListItem::new(format!("{} ({})", profile.label, profile.id)))
            .collect::<Vec<_>>()
    };
    let list = List::new(items)
        .block(Block::default().title("Profiles").borders(Borders::ALL))
        .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");
    let mut list_state = ListState::default().with_selected(Some(app.profile_cursor));
    frame.render_stateful_widget(list, chunks[0], &mut list_state);

    let mut help_lines = vec![
        Line::from("Setup screen"),
        Line::from(""),
        Line::from("Enter attaches to the selected profile."),
        Line::from("s starts or stops the profile daemon."),
        Line::from("r refreshes profile state."),
        Line::from("e exports the selected profile to shell state exports/."),
        Line::from(""),
        Line::from("Import/export remains available through the CLI in this slice:"),
        Line::from("  igloo-shell setup"),
        Line::from("  igloo-shell profile import"),
        Line::from("  igloo-shell profile export"),
        Line::from(""),
        Line::from(format!("Daemon running: {}", yes_no(app.daemon_running))),
    ];
    if let Some(path) = &app.last_export_path {
        help_lines.push(Line::from(format!("Last export: {path}")));
    }
    let help = Paragraph::new(Text::from(help_lines))
    .block(Block::default().title("Setup").borders(Borders::ALL))
    .wrap(Wrap { trim: true });
    frame.render_widget(help, chunks[1]);

    if app.active_profile.is_none() && !app.profiles.is_empty() {
        let popup = centered_rect(60, 20, area);
        frame.render_widget(Clear, popup);
        let widget = Paragraph::new("Select a profile and press Enter")
            .block(Block::default().title("Profile Picker").borders(Borders::ALL));
        frame.render_widget(widget, popup);
    }
}

fn read_log_lines(path: &std::path::Path, verbose: bool) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)?;
    let mut lines = raw.lines().map(|line| line.to_string()).collect::<Vec<_>>();
    if !verbose && lines.len() > LOG_TAIL_LINES {
        lines = lines.split_off(lines.len() - LOG_TAIL_LINES);
    }
    Ok(lines)
}

fn parse_policy_document(value: &serde_json::Value) -> Result<PolicyOverridesDocument> {
    if value.is_null() {
        return Ok(PolicyOverridesDocument {
            default_policy: None,
            peer_overrides: Vec::new(),
        });
    }
    if let Ok(peer_overrides) = serde_json::from_value::<Vec<PolicyPeerOverride>>(value.clone()) {
        return Ok(PolicyOverridesDocument {
            default_policy: None,
            peer_overrides,
        });
    }
    Ok(serde_json::from_value(value.clone())?)
}

fn policy_rows(app: &App) -> Vec<(String, PeerPolicy, bool)> {
    let mut rows = Vec::new();
    let document = app
        .active_profile
        .as_ref()
        .and_then(|profile| parse_policy_document(&profile.policy_overrides).ok())
        .unwrap_or(PolicyOverridesDocument {
            default_policy: None,
            peer_overrides: Vec::new(),
        });
    let default_policy = document.default_policy.clone().unwrap_or_default();
    let overrides = document
        .peer_overrides
        .into_iter()
        .map(|entry| (entry.pubkey, entry.policy))
        .collect::<BTreeMap<_, _>>();

    let peers = app
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.runtime.metadata.peers.clone())
        .unwrap_or_default();
    for peer in peers {
        if let Some(policy) = overrides.get(&peer) {
            rows.push((peer, policy.clone(), true));
        } else {
            rows.push((peer, default_policy.clone(), false));
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

fn next_policy(policy: PeerPolicy) -> PeerPolicy {
    match (policy.request.sign, policy.respond.sign) {
        (true, true) => PeerPolicy::from_send_receive(true, false),
        (true, false) => PeerPolicy::from_send_receive(false, true),
        (false, true) => PeerPolicy::from_send_receive(false, false),
        (false, false) => PeerPolicy::from_send_receive(true, true),
    }
}

fn policy_mode_label(policy: &PeerPolicy) -> &'static str {
    match (policy.request.sign, policy.respond.sign) {
        (true, true) => "send+receive",
        (true, false) => "send-only",
        (false, true) => "receive-only",
        (false, false) => "blocked",
    }
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
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string())
}

fn in_profile_selection(app: &App) -> bool {
    app.active_profile.is_none() || app.active_screen == Screen::Setup
}

fn export_selected_profile(paths: &ShellPaths, app: &mut App) -> Result<()> {
    let profile = if app.active_screen == Screen::Setup && !app.profiles.is_empty() {
        app.profiles
            .get(app.profile_cursor)
            .cloned()
            .ok_or_else(|| anyhow!("invalid profile selection"))?
    } else {
        app.active_profile
            .clone()
            .ok_or_else(|| anyhow!("no active profile"))?
    };

    let export_root = paths.state_dir.join("exports").join(&profile.id);
    let out_dir = export_root.join(now_unix_secs().to_string());
    let result = export_profile(paths, &profile.id, &out_dir, None)?;
    app.last_export_path = Some(result.out_dir.clone());
    app.status_line = format!("Exported profile {} to {}", profile.id, result.out_dir);
    Ok(())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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
    use crate::shell::ProfileManifest;
    use serde_json::Value;

    fn sample_app() -> App {
        let mut app = App::new(None);
        app.profiles = vec![
            ProfileManifest {
                id: "alpha".to_string(),
                label: "Alpha".to_string(),
                group_ref: "group.json".to_string(),
                share_ref: "vault-1".to_string(),
                relay_profile: "local".to_string(),
                runtime_options: Value::Null,
                policy_overrides: Value::Null,
                state_path: "state.bin".to_string(),
                daemon_socket_path: "/tmp/alpha.sock".to_string(),
                created_at: 1,
                last_used_at: Some(1),
            },
            ProfileManifest {
                id: "beta".to_string(),
                label: "Beta".to_string(),
                group_ref: "group.json".to_string(),
                share_ref: "vault-2".to_string(),
                relay_profile: "local".to_string(),
                runtime_options: Value::Null,
                policy_overrides: Value::Null,
                state_path: "state.bin".to_string(),
                daemon_socket_path: "/tmp/beta.sock".to_string(),
                created_at: 1,
                last_used_at: Some(1),
            },
        ];
        app
    }

    #[test]
    fn setup_profile_selection_uses_profile_cursor() {
        let mut app = sample_app();
        app.active_screen = Screen::Setup;
        app.profile_cursor = 1;
        assert!(in_profile_selection(&app));
        attach_selected_profile(&mut app).expect("attach profile");
        assert_eq!(app.active_profile_id.as_deref(), Some("beta"));
    }

    #[test]
    fn overview_pending_operations_are_clamped_by_screen_rows() {
        let mut app = sample_app();
        app.active_profile_id = Some("alpha".to_string());
        app.active_profile = Some(app.profiles[0].clone());
        app.active_screen = Screen::Peers;
        app.snapshot = Some(DaemonSnapshot {
            runtime: RuntimeStatusView {
                status: DeviceStatusView {
                    device_id: "device".to_string(),
                    pending_ops: 0,
                    last_active: 1,
                    known_peers: 1,
                    request_seq: 1,
                },
                metadata: RuntimeMetadataView {
                    device_id: "device".to_string(),
                    member_idx: 1,
                    share_public_key: "share".to_string(),
                    group_public_key: "group".to_string(),
                    peers: vec!["peer1".to_string()],
                },
                readiness: RuntimeReadinessView {
                    runtime_ready: true,
                    restore_complete: true,
                    sign_ready: true,
                    ecdh_ready: true,
                    threshold: 1,
                    signing_peer_count: 1,
                    ecdh_peer_count: 1,
                    last_refresh_at: Some(1),
                    degraded_reasons: Vec::new(),
                },
                peers: vec![PeerStatusView {
                    idx: 2,
                    pubkey: "peer1".to_string(),
                    known: true,
                    last_seen: Some(1),
                    online: true,
                    incoming_available: 1,
                    outgoing_available: 1,
                    outgoing_spent: 0,
                    can_sign: true,
                    should_send_nonces: true,
                }],
                pending_operations: vec![PendingOperationView {
                    op_type: "ping".to_string(),
                    request_id: "req-1".to_string(),
                    started_at: 1,
                    timeout_at: 2,
                    target_peers: vec!["peer1".to_string()],
                    threshold: 1,
                }],
            },
            invites: Vec::new(),
            policies: BTreeMap::new(),
        });
        app.row_cursor = 99;
        clamp_row_cursor(&mut app);
        assert_eq!(app.row_cursor, 0);
    }
}
