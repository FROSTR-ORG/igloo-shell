use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use bifrost_codec::wire::{GroupPackageWire, SharePackageWire};
use frostr_utils::{CreateKeysetConfig, create_keyset};
use serde::Serialize;

const DEFAULT_NAMES: [&str; 20] = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "karl",
    "laura", "mallory", "nia", "oscar", "peggy", "quentin", "ruth", "sybil", "trent",
];

#[derive(Debug, Clone, Serialize)]
struct DeviceConfig {
    group_path: String,
    share_path: String,
    state_path: String,
    relays: Vec<String>,
    peers: Vec<DevicePeerConfig>,
    options: DeviceOptions,
}

#[derive(Debug, Clone, Serialize)]
struct DevicePeerConfig {
    pubkey: String,
    policy: PeerPolicyConfig,
}

#[derive(Debug, Clone, Serialize)]
struct PeerPolicyConfig {
    block_all: bool,
    request: MethodPolicyConfig,
    respond: MethodPolicyConfig,
}

#[derive(Debug, Clone, Serialize)]
struct MethodPolicyConfig {
    echo: bool,
    ping: bool,
    onboard: bool,
    sign: bool,
    ecdh: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceOptions {
    sign_timeout_secs: u64,
    ecdh_timeout_secs: u64,
    ping_timeout_secs: u64,
    onboard_timeout_secs: u64,
    request_ttl_secs: u64,
    max_future_skew_secs: u64,
    request_cache_limit: usize,
    ecdh_cache_capacity: usize,
    ecdh_cache_ttl_secs: u64,
    sig_cache_capacity: usize,
    sig_cache_ttl_secs: u64,
    state_save_interval_secs: u64,
    event_kind: u64,
    peer_selection_strategy: String,
    router_expire_tick_ms: u64,
    router_relay_backoff_ms: u64,
    router_command_queue_capacity: usize,
    router_inbound_queue_capacity: usize,
    router_outbound_queue_capacity: usize,
    router_command_overflow_policy: String,
    router_inbound_overflow_policy: String,
    router_outbound_overflow_policy: String,
    router_inbound_dedupe_cache_limit: usize,
}

pub fn run_keygen_command(args: &[String]) -> Result<()> {
    let out_dir = arg_value(args, "--out-dir").unwrap_or_else(|| "dev/data".to_string());
    let threshold = arg_value(args, "--threshold")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(2);
    let count = arg_value(args, "--count")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(3);
    let relay = arg_value(args, "--relay").unwrap_or_else(|| "ws://127.0.0.1:8194".to_string());

    if threshold < 2 {
        return Err(anyhow!("threshold must be >= 2"));
    }
    if count < threshold {
        return Err(anyhow!("count must be >= threshold"));
    }
    if count as usize > DEFAULT_NAMES.len() {
        return Err(anyhow!("count exceeds built-in member names"));
    }

    let out_path = PathBuf::from(out_dir);
    fs::create_dir_all(&out_path).with_context(|| format!("create {}", out_path.display()))?;

    let bundle = create_keyset(CreateKeysetConfig { threshold, count })
        .map_err(|e| anyhow!("create keyset: {e}"))?;
    let group = bundle.group;
    let share_packages = bundle.shares;
    let members = group.members.clone();

    write_json(
        &out_path.join("group.json"),
        &GroupPackageWire::from(group.clone()),
    )?;

    let selected_names = DEFAULT_NAMES[..count as usize].to_vec();
    for (i, share) in share_packages.iter().enumerate() {
        let name = selected_names
            .get(i)
            .ok_or_else(|| anyhow!("missing name for member index {i}"))?;
        let path = out_path.join(format!("share-{name}.json"));
        write_json(&path, &SharePackageWire::from(share.clone()))?;
    }

    for (i, share) in share_packages.iter().enumerate() {
        let name = selected_names
            .get(i)
            .ok_or_else(|| anyhow!("missing name for member index {i}"))?;

        let peers = members
            .iter()
            .filter(|m| m.idx != share.idx)
            .map(|m| DevicePeerConfig {
                pubkey: hex::encode(&m.pubkey[1..]),
                policy: PeerPolicyConfig {
                    block_all: false,
                    request: MethodPolicyConfig {
                        echo: true,
                        ping: true,
                        onboard: true,
                        sign: true,
                        ecdh: true,
                    },
                    respond: MethodPolicyConfig {
                        echo: true,
                        ping: true,
                        onboard: true,
                        sign: true,
                        ecdh: true,
                    },
                },
            })
            .collect::<Vec<_>>();

        let config = DeviceConfig {
            group_path: out_path.join("group.json").display().to_string(),
            share_path: out_path
                .join(format!("share-{name}.json"))
                .display()
                .to_string(),
            state_path: out_path
                .join(format!("state-{name}.json"))
                .display()
                .to_string(),
            relays: vec![relay.clone()],
            peers,
            options: DeviceOptions {
                sign_timeout_secs: 30,
                ecdh_timeout_secs: 30,
                ping_timeout_secs: 15,
                onboard_timeout_secs: 30,
                request_ttl_secs: 300,
                max_future_skew_secs: 30,
                request_cache_limit: 2048,
                ecdh_cache_capacity: 256,
                ecdh_cache_ttl_secs: 300,
                sig_cache_capacity: 256,
                sig_cache_ttl_secs: 120,
                state_save_interval_secs: 30,
                event_kind: 20_000,
                peer_selection_strategy: "deterministic_sorted".to_string(),
                router_expire_tick_ms: 1000,
                router_relay_backoff_ms: 50,
                router_command_queue_capacity: 128,
                router_inbound_queue_capacity: 4096,
                router_outbound_queue_capacity: 1024,
                router_command_overflow_policy: "fail".to_string(),
                router_inbound_overflow_policy: "drop_oldest".to_string(),
                router_outbound_overflow_policy: "fail".to_string(),
                router_inbound_dedupe_cache_limit: 16_384,
            },
        };

        write_json(&out_path.join(format!("igloo-shell-{name}.json")), &config)?;
    }

    println!("devnet material generated in {}", out_path.display());
    println!("members: {}", selected_names.join(", "));
    println!("threshold: {threshold}-of-{count}");
    println!("relay: {relay}");
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let raw = serde_json::to_string_pretty(value).context("serialize json")?;
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == key {
            return args.get(i + 1).cloned();
        }
    }
    None
}
