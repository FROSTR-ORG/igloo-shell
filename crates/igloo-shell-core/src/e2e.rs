use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

const DEFAULT_RELAY: &str = "ws://127.0.0.1:8194";
const DEFAULT_VAULT_PASSPHRASE: &str = "igloo-shell-e2e-passphrase";

pub fn run_e2e_node_command(args: &[String]) -> Result<()> {
    let mut out_dir: Option<PathBuf> = None;
    let mut relay = DEFAULT_RELAY.to_string();

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--out-dir" => {
                let value = args
                    .get(idx + 1)
                    .context("missing value for --out-dir")?
                    .clone();
                out_dir = Some(PathBuf::from(value));
                idx += 2;
            }
            "--relay" => {
                relay = args
                    .get(idx + 1)
                    .context("missing value for --relay")?
                    .clone();
                idx += 2;
            }
            "help" | "--help" | "-h" => return Ok(()),
            other => bail!("unknown e2e-node argument: {other}"),
        }
    }

    let root = workspace_root()?;
    let out_dir = out_dir.unwrap_or_else(|| root.join("dev/data"));
    let work_dir = out_dir.join("managed-e2e-node");
    let logs_dir = work_dir.join("logs");
    fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;
    let out_file = logs_dir.join("node-e2e-output.txt");
    fs::write(&out_file, "").with_context(|| format!("create {}", out_file.display()))?;

    let mut devnet = ManagedDevnet::provision(&root, &work_dir, &relay, 2, 3)?;
    run_sign_iterations(&mut devnet, &out_file, 1, 1)?;
    run_ecdh_iterations(&mut devnet, &out_file, 1, 1)?;
    append_output(&out_file, "summary", "node e2e passed")?;

    println!("node e2e passed");
    Ok(())
}

pub fn run_e2e_full_command(args: &[String]) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = args;
        bail!("e2e-full currently requires a unix target");
    }
    #[cfg(unix)]
    {
        let mut out_dir: Option<PathBuf> = None;
        let mut relay = DEFAULT_RELAY.to_string();
        let mut threshold = 11u16;
        let mut count = 15u16;
        let mut sign_iterations = 20usize;
        let mut ecdh_iterations = 20usize;
        let mut seed = 1u64;

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--out-dir" => {
                    out_dir = Some(PathBuf::from(
                        args.get(idx + 1).context("missing value for --out-dir")?,
                    ));
                    idx += 2;
                }
                "--relay" => {
                    relay = args
                        .get(idx + 1)
                        .context("missing value for --relay")?
                        .clone();
                    idx += 2;
                }
                "--threshold" => {
                    threshold = args
                        .get(idx + 1)
                        .context("missing value for --threshold")?
                        .parse()
                        .context("invalid --threshold")?;
                    idx += 2;
                }
                "--count" => {
                    count = args
                        .get(idx + 1)
                        .context("missing value for --count")?
                        .parse()
                        .context("invalid --count")?;
                    idx += 2;
                }
                "--sign-iterations" => {
                    sign_iterations = args
                        .get(idx + 1)
                        .context("missing value for --sign-iterations")?
                        .parse()
                        .context("invalid --sign-iterations")?;
                    idx += 2;
                }
                "--ecdh-iterations" => {
                    ecdh_iterations = args
                        .get(idx + 1)
                        .context("missing value for --ecdh-iterations")?
                        .parse()
                        .context("invalid --ecdh-iterations")?;
                    idx += 2;
                }
                "--seed" => {
                    seed = args
                        .get(idx + 1)
                        .context("missing value for --seed")?
                        .parse()
                        .context("invalid --seed")?;
                    idx += 2;
                }
                "help" | "--help" | "-h" => return Ok(()),
                other => bail!("unknown e2e-full argument: {other}"),
            }
        }

        if count < threshold || threshold < 2 {
            bail!("e2e-full requires count >= threshold >= 2");
        }

        let root = workspace_root()?;
        let out_dir = out_dir.unwrap_or_else(|| root.join("dev/data"));
        let work_dir = out_dir.join("managed-e2e-full");
        let logs_dir = work_dir.join("logs");
        fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;
        let out_file = logs_dir.join("node-e2e-full-output.txt");
        fs::write(&out_file, "").with_context(|| format!("create {}", out_file.display()))?;

        let mut devnet = ManagedDevnet::provision(&root, &work_dir, &relay, threshold, count)?;
        run_policy_round_trip(&mut devnet, &out_file)?;
        run_sign_iterations(&mut devnet, &out_file, sign_iterations, seed)?;
        run_ecdh_iterations(&mut devnet, &out_file, ecdh_iterations, seed)?;
        append_output(&out_file, "summary", "e2e-full passed")?;

        println!("node e2e-full passed");
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ManagedShellEnv {
    xdg_config_home: PathBuf,
    xdg_data_home: PathBuf,
    xdg_state_home: PathBuf,
    vault_passphrase: String,
}

impl ManagedShellEnv {
    fn for_work_dir(work_dir: &Path) -> Self {
        Self {
            xdg_config_home: work_dir.join("config"),
            xdg_data_home: work_dir.join("data"),
            xdg_state_home: work_dir.join("state"),
            vault_passphrase: DEFAULT_VAULT_PASSPHRASE.to_string(),
        }
    }

    fn apply(&self, command: &mut Command) {
        command.env("XDG_CONFIG_HOME", &self.xdg_config_home);
        command.env("XDG_DATA_HOME", &self.xdg_data_home);
        command.env("XDG_STATE_HOME", &self.xdg_state_home);
        command.env("IGLOO_SHELL_VAULT_PASSPHRASE", &self.vault_passphrase);
    }
}

#[derive(Debug, Clone)]
struct NodeHandle {
    member: String,
    profile_id: String,
}

#[derive(Debug)]
struct ManagedDevnet {
    shell_exe: PathBuf,
    shell_env: ManagedShellEnv,
    relay_child: Option<Child>,
    profiles: Vec<NodeHandle>,
}

impl ManagedDevnet {
    fn provision(
        root: &Path,
        work_dir: &Path,
        relay_url: &str,
        threshold: u16,
        count: u16,
    ) -> Result<Self> {
        if work_dir.exists() {
            fs::remove_dir_all(work_dir)
                .with_context(|| format!("remove {}", work_dir.display()))?;
        }
        let material_dir = work_dir.join("material");
        let logs_dir = work_dir.join("logs");
        fs::create_dir_all(&material_dir)
            .with_context(|| format!("create {}", material_dir.display()))?;
        fs::create_dir_all(&logs_dir).with_context(|| format!("create {}", logs_dir.display()))?;

        let shell_exe = std::env::current_exe().context("resolve current executable")?;
        let shell_env = ManagedShellEnv::for_work_dir(work_dir);

        run_shell(
            &shell_exe,
            None,
            &[
                "dev",
                "keygen",
                "--out-dir",
                path_arg(&material_dir)?,
                "--threshold",
                &threshold.to_string(),
                "--count",
                &count.to_string(),
                "--relay",
                relay_url,
            ],
        )?;

        let relay_child = Some(start_relay_process(
            &shell_exe,
            relay_url,
            &logs_dir.join("relay.log"),
        )?);

        run_shell(
            &shell_exe,
            Some(&shell_env),
            &["relays", "set", "local", relay_url],
        )?;

        let mut profiles = import_profiles(&shell_exe, &shell_env, &material_dir)?;
        profiles.sort_by(|a, b| a.member.cmp(&b.member));
        for node in &profiles {
            run_shell(
                &shell_exe,
                Some(&shell_env),
                &["daemon", "start", "--profile", &node.profile_id],
            )?;
            wait_for_runtime(&shell_exe, &shell_env, &node.profile_id, Duration::from_secs(30))?;
        }

        let mut devnet = Self {
            shell_exe,
            shell_env,
            relay_child,
            profiles,
        };
        prepare_alice_peers(&mut devnet)?;
        let _ = root;
        Ok(devnet)
    }

    fn alice(&self) -> Result<&NodeHandle> {
        self.profiles
            .iter()
            .find(|node| node.member == "alice")
            .ok_or_else(|| anyhow!("missing alice profile"))
    }

    fn alice_peer_pubkeys(&self) -> Result<Vec<String>> {
        let alice = self.alice()?;
        let peers = run_shell_json(
            &self.shell_exe,
            Some(&self.shell_env),
            &["peer", "list", "--profile", &alice.profile_id],
        )?;
        let entries = peers
            .as_array()
            .ok_or_else(|| anyhow!("peer list returned invalid json"))?;
        Ok(entries
            .iter()
            .filter_map(|entry| entry.get("pubkey").and_then(Value::as_str))
            .map(ToString::to_string)
            .collect())
    }

    fn stop_all(&mut self) {
        for node in &self.profiles {
            let _ = run_shell(
                &self.shell_exe,
                Some(&self.shell_env),
                &["daemon", "stop", "--profile", &node.profile_id],
            );
        }
        if let Some(child) = &mut self.relay_child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.relay_child = None;
    }
}

impl Drop for ManagedDevnet {
    fn drop(&mut self) {
        self.stop_all();
    }
}

fn import_profiles(
    shell_exe: &Path,
    shell_env: &ManagedShellEnv,
    material_dir: &Path,
) -> Result<Vec<NodeHandle>> {
    let mut members = Vec::new();
    for entry in fs::read_dir(material_dir).with_context(|| format!("read {}", material_dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(member) = name
            .strip_prefix("share-")
            .and_then(|value| value.strip_suffix(".json"))
        else {
            continue;
        };
        let result = run_shell_json(
            shell_exe,
            Some(shell_env),
            &[
                "profile",
                "import",
                "--group",
                path_arg(&material_dir.join("group.json"))?,
                "--share",
                path_arg(&path)?,
                "--label",
                member,
                "--relay-profile",
                "local",
            ],
        )?;
        let profile_id = extract_json_string_field(&result, "id")
            .ok_or_else(|| anyhow!("profile import result did not include id"))?;
        members.push(NodeHandle {
            member: member.to_string(),
            profile_id,
        });
    }
    if members.is_empty() {
        bail!("no share packages found in {}", material_dir.display());
    }
    Ok(members)
}

fn prepare_alice_peers(devnet: &mut ManagedDevnet) -> Result<()> {
    let alice = devnet.alice()?.clone();
    let peers = wait_for_peer_list(
        &devnet.shell_exe,
        &devnet.shell_env,
        &alice.profile_id,
        devnet.profiles.len().saturating_sub(1),
        Duration::from_secs(30),
    )?;
    for peer in peers {
        run_shell(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["peer", "ping", "--profile", &alice.profile_id, &peer],
        )?;
        run_shell(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["peer", "onboard", "--profile", &alice.profile_id, &peer],
        )?;
    }
    wait_for_signing_readiness(devnet, Duration::from_secs(30))
}

fn wait_for_runtime(
    shell_exe: &Path,
    shell_env: &ManagedShellEnv,
    profile_id: &str,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if run_shell_json(
            shell_exe,
            Some(shell_env),
            &["runtime", "status", "--profile", profile_id],
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("timed out waiting for runtime status for profile {profile_id}")
}

fn wait_for_peer_list(
    shell_exe: &Path,
    shell_env: &ManagedShellEnv,
    profile_id: &str,
    expected_min: usize,
    timeout: Duration,
) -> Result<Vec<String>> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let peers = run_shell_json(
            shell_exe,
            Some(shell_env),
            &["peer", "list", "--profile", profile_id],
        )?;
        let values = peers
            .as_array()
            .ok_or_else(|| anyhow!("peer list returned invalid json"))?;
        let pubkeys = values
            .iter()
            .filter_map(|entry| entry.get("pubkey").and_then(Value::as_str))
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if pubkeys.len() >= expected_min {
            return Ok(pubkeys);
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("timed out waiting for peer list for profile {profile_id}")
}

fn wait_for_signing_readiness(devnet: &ManagedDevnet, timeout: Duration) -> Result<()> {
    let alice = devnet.alice()?;
    let start = Instant::now();
    while start.elapsed() < timeout {
        let status = run_shell_json(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["runtime", "status", "--profile", &alice.profile_id],
        )?;
        let readiness = status
            .get("readiness")
            .ok_or_else(|| anyhow!("runtime status missing readiness"))?;
        let sign_ready = readiness
            .get("sign_ready")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ecdh_ready = readiness
            .get("ecdh_ready")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if sign_ready && ecdh_ready {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("timed out waiting for alice sign/ecdh readiness")
}

fn run_sign_iterations(
    devnet: &mut ManagedDevnet,
    out_file: &Path,
    iterations: usize,
    seed: u64,
) -> Result<()> {
    let alice = devnet.alice()?.clone();
    for idx in 0..iterations {
        let message = format!("{:064x}", seed + idx as u64 + 1);
        let output = run_shell_json(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["runtime", "sign", "--profile", &alice.profile_id, &message],
        )?;
        let signature = output
            .get("signatures_hex")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("sign result missing signatures_hex"))?;
        if signature.len() != 128 || !signature.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("invalid signature output length: {}", signature.len());
        }
        append_output(
            out_file,
            &format!("sign-{idx}"),
            &serde_json::to_string_pretty(&output)?,
        )?;
    }
    Ok(())
}

fn run_policy_round_trip(devnet: &mut ManagedDevnet, out_file: &Path) -> Result<()> {
    let alice = devnet.alice()?.clone();
    let target_peer = devnet
        .alice_peer_pubkeys()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("missing peer pubkey for policy round trip"))?;

    let set_default = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &[
            "policy",
            "set-default",
            "--profile",
            &alice.profile_id,
            "--send",
            "false",
            "--receive",
            "true",
        ],
    )?;
    if set_default
        .get("restart_required")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("policy set-default did not request restart");
    }
    append_output(
        out_file,
        "policy-set-default",
        &serde_json::to_string_pretty(&set_default)?,
    )?;

    run_shell_with_retry(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &["daemon", "restart", "--profile", &alice.profile_id],
        3,
    )?;
    wait_for_runtime(
        &devnet.shell_exe,
        &devnet.shell_env,
        &alice.profile_id,
        Duration::from_secs(30),
    )?;

    let set_peer = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &[
            "policy",
            "set-peer",
            "--profile",
            &alice.profile_id,
            &target_peer,
            "--send",
            "true",
            "--receive",
            "false",
        ],
    )?;
    if set_peer.get("updated").and_then(Value::as_bool) != Some(true)
        || set_peer.get("persisted").and_then(Value::as_bool) != Some(true)
    {
        bail!("policy set-peer did not report success");
    }
    append_output(
        out_file,
        "policy-set-peer",
        &serde_json::to_string_pretty(&set_peer)?,
    )?;

    let live = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &["policy", "show", "--profile", &alice.profile_id],
    )?;
    let live_entry = live
        .as_array()
        .and_then(|items| {
            items.iter()
                .find(|entry| entry.get("pubkey").and_then(Value::as_str) == Some(target_peer.as_str()))
        })
        .ok_or_else(|| anyhow!("policy show missing peer {target_peer}"))?;
    if live_entry
        .get("policy")
        .and_then(|policy| policy.get("request"))
        .and_then(|request| request.get("sign"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("policy show did not reflect peer send=true");
    }
    append_output(
        out_file,
        "policy-show",
        &serde_json::to_string_pretty(&live)?,
    )?;

    let cleared = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &["policy", "clear-peer", "--profile", &alice.profile_id, &target_peer],
    )?;
    if cleared.get("updated").and_then(Value::as_bool) != Some(true)
        || cleared.get("persisted").and_then(Value::as_bool) != Some(true)
    {
        bail!("policy clear-peer did not report success");
    }
    append_output(
        out_file,
        "policy-clear-peer",
        &serde_json::to_string_pretty(&cleared)?,
    )?;

    let manifest = run_shell_json(
        &devnet.shell_exe,
        Some(&devnet.shell_env),
        &["profile", "show", &alice.profile_id],
    )?;
    let overrides = manifest
        .get("policy_overrides")
        .and_then(|value| value.get("peer_overrides"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("profile show missing peer_overrides"))?;
    if !overrides.is_empty() {
        bail!("policy clear-peer left peer overrides behind");
    }
    append_output(
        out_file,
        "policy-profile-show",
        &serde_json::to_string_pretty(&manifest)?,
    )?;

    Ok(())
}

fn run_ecdh_iterations(
    devnet: &mut ManagedDevnet,
    out_file: &Path,
    iterations: usize,
    seed: u64,
) -> Result<()> {
    let alice = devnet.alice()?.clone();
    let target_peer = devnet
        .alice_peer_pubkeys()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("missing peer pubkey for ecdh"))?;
    for idx in 0..iterations {
        let _ = seed + idx as u64;
        let output = run_shell_json(
            &devnet.shell_exe,
            Some(&devnet.shell_env),
            &["runtime", "ecdh", "--profile", &alice.profile_id, &target_peer],
        )?;
        let secret = output
            .get("shared_secret_hex32")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ecdh result missing shared_secret_hex32"))?;
        if secret.len() != 64 || !secret.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("invalid ecdh output length: {}", secret.len());
        }
        append_output(
            out_file,
            &format!("ecdh-{idx}"),
            &serde_json::to_string_pretty(&output)?,
        )?;
    }
    Ok(())
}

fn start_relay_process(shell_exe: &Path, relay: &str, log_path: &Path) -> Result<Child> {
    let url = relay
        .strip_prefix("ws://")
        .ok_or_else(|| anyhow!("relay must be ws://host:port"))?;
    let (host, port) = url
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("relay must include port"))?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let err = log.try_clone().with_context(|| format!("clone {}", log_path.display()))?;
    let child = Command::new(shell_exe)
        .args(["dev", "relay", "--host", host, "--port", port])
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .context("spawn relay process")?;
    thread::sleep(Duration::from_secs(1));
    Ok(child)
}

fn run_shell(shell_exe: &Path, shell_env: Option<&ManagedShellEnv>, args: &[&str]) -> Result<()> {
    let status = build_shell_command(shell_exe, shell_env, args)
        .status()
        .context("run igloo-shell")?;
    if !status.success() {
        bail!("igloo-shell failed: {status}");
    }
    Ok(())
}

fn run_shell_with_retry(
    shell_exe: &Path,
    shell_env: Option<&ManagedShellEnv>,
    args: &[&str],
    retries: usize,
) -> Result<()> {
    let attempts = retries.max(1);
    let mut last_error = None;
    for _ in 0..attempts {
        match run_shell(shell_exe, shell_env, args) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("igloo-shell retry failed")))
}

fn run_shell_json(
    shell_exe: &Path,
    shell_env: Option<&ManagedShellEnv>,
    args: &[&str],
) -> Result<Value> {
    let output = build_shell_command(shell_exe, shell_env, args)
        .output()
        .context("capture igloo-shell output")?;
    if !output.status.success() {
        bail!(
            "igloo-shell failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse igloo-shell json output")
}

fn build_shell_command(
    shell_exe: &Path,
    shell_env: Option<&ManagedShellEnv>,
    args: &[&str],
) -> Command {
    let mut command = Command::new(shell_exe);
    if let Some(shell_env) = shell_env {
        shell_env.apply(&mut command);
    }
    command.args(args);
    command
}

fn append_output(path: &Path, label: &str, output: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "== {label} ==")?;
    writeln!(file, "{output}")?;
    Ok(())
}

fn extract_json_string_field(value: &Value, field: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(field).and_then(Value::as_str) {
                return Some(found.to_string());
            }
            map.values()
                .find_map(|entry| extract_json_string_field(entry, field))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|entry| extract_json_string_field(entry, field)),
        _ => None,
    }
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("invalid path {}", path.display()))
}

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("resolve workspace root"))
}
