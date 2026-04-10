use anyhow::{Result, anyhow};
use bifrost_signer::PeerStatus;
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    RelayProfile, ShellPaths, daemon_runtime_status, load_shell_config, now_unix_secs,
    probe_relays, read_profile, read_relay_profile,
};

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

fn peer_pubkeys_by<F>(peers: &[PeerStatus], predicate: F) -> Vec<String>
where
    F: Fn(&PeerStatus) -> bool,
{
    peers
        .iter()
        .filter(|peer| predicate(peer))
        .map(|peer| peer.pubkey.clone())
        .collect()
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
    let profile: RelayProfile = read_relay_profile(paths, &selected)?;
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

    let runtime_status = daemon_runtime_status(paths, profile_id).await;
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
            share_public_key = Some(status.metadata.share_public_key.clone());
            group_public_key = Some(status.metadata.group_public_key.clone());
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
            let restore_complete = status.readiness.restore_complete;
            let peer_callback_ready = share_public_key.is_some() && group_public_key.is_some();
            let online_peer_count = status.peers.iter().filter(|peer| peer.online).count();
            let known_peer_count = status.status.known_peers as u64;
            let degraded_reasons = serde_json::to_value(&status.readiness.degraded_reasons)
                .unwrap_or_else(|_| Value::Array(Vec::new()));
            details["restore_complete"] = Value::Bool(restore_complete);
            details["peer_callback_ready"] = Value::Bool(peer_callback_ready);
            details["known_peer_count"] = Value::Number(known_peer_count.into());
            details["online_peer_count"] = Value::Number((online_peer_count as u64).into());
            details["degraded_reasons"] = degraded_reasons;
            reasons_not_ready.is_empty() && runtime_online && peer_callback_ready
        }
        ShellCheckKind::Sign => {
            let readiness = status.readiness.clone();
            let peers = &status.peers;
            let sign_ready = readiness.sign_ready;
            let threshold = readiness.threshold;
            let sign_responder_peers =
                peer_pubkeys_by(peers, |peer| peer.online && peer.outgoing_available > 0);
            let sign_initiator_peers = peer_pubkeys_by(peers, |peer| peer.can_sign);
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
            let restore_complete = readiness.restore_complete;
            let degraded_reasons = serde_json::to_value(&readiness.degraded_reasons)
                .unwrap_or_else(|_| Value::Array(Vec::new()));
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

            details["readiness"] = serde_json::to_value(&readiness)
                .unwrap_or_else(|_| Value::Object(Default::default()));
            details["sign_initiator_peer_count"] =
                Value::Number((sign_initiator_peers.len() as u64).into());
            details["sign_responder_peer_count"] =
                Value::Number((sign_responder_peers.len() as u64).into());
            details["sign_initiator_peers"] = json!(sign_initiator_peers);
            details["sign_responder_peers"] = json!(sign_responder_peers);
            details["missing_sign_initiator_peers"] = json!(missing_initiators);
            details["missing_sign_responder_peers"] = json!(missing_responders);
            reasons_not_ready.is_empty()
        }
        ShellCheckKind::Ecdh => {
            let readiness = status.readiness.clone();
            let peers = &status.peers;
            let ecdh_ready = readiness.ecdh_ready;
            let ecdh_ready_peers = peer_pubkeys_by(peers, |peer| peer.online);
            let all_peer_pubkeys = peer_pubkeys_by(peers, |_| true);
            let missing_ecdh = all_peer_pubkeys
                .iter()
                .filter(|pubkey| !ecdh_ready_peers.contains(pubkey))
                .cloned()
                .collect::<Vec<_>>();
            let restore_complete = readiness.restore_complete;
            let degraded_reasons = serde_json::to_value(&readiness.degraded_reasons)
                .unwrap_or_else(|_| Value::Array(Vec::new()));

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

            details["readiness"] = serde_json::to_value(&readiness)
                .unwrap_or_else(|_| Value::Object(Default::default()));
            details["ecdh_peer_count"] = Value::Number((ecdh_ready_peers.len() as u64).into());
            details["ecdh_ready_peers"] = json!(ecdh_ready_peers);
            details["missing_ecdh_peers"] = json!(missing_ecdh);
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
