#![allow(dead_code)]

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

pub struct TestHarness {
    root: PathBuf,
    bin: PathBuf,
    tag: String,
    relay_url: String,
    relay_child: Option<Child>,
    _guard: MutexGuard<'static, ()>,
}

pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|err| {
            panic!(
                "expected json output: {err}\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

impl TestHarness {
    pub fn new(name: &str) -> Self {
        let guard = global_test_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("igloo-shell-cli-tests-{name}-{unique}"));
        fs::create_dir_all(&root).expect("create temp root");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind relay port");
        let port = listener.local_addr().expect("relay local addr").port();
        drop(listener);
        let relay_url = format!("ws://127.0.0.1:{port}");
        let bin = PathBuf::from(env!("CARGO_BIN_EXE_igloo-shell"));
        Self {
            root,
            bin,
            tag: unique.to_string(),
            relay_url,
            relay_child: None,
            _guard: guard,
        }
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn material_dir(&self) -> PathBuf {
        self.root.join("material")
    }

    pub fn config_home(&self) -> PathBuf {
        self.root.join("config")
    }

    pub fn data_home(&self) -> PathBuf {
        self.root.join("data")
    }

    pub fn state_home(&self) -> PathBuf {
        self.root.join("state")
    }

    pub fn daemon_log_path(&self, profile_id: &str) -> PathBuf {
        self.state_home()
            .join("igloo-shell")
            .join("profiles")
            .join(profile_id)
            .join("daemon.log")
    }

    pub fn shell_data_dir(&self) -> PathBuf {
        self.data_home().join("igloo-shell")
    }

    pub fn vault_dir(&self) -> PathBuf {
        self.shell_data_dir().join("vault")
    }

    pub fn run(&self, args: &[&str]) -> CommandResult {
        let output = self.command(args).output().expect("run igloo-shell");
        assert!(
            output.status.success(),
            "command failed: {}\nstdout:\n{}\nstderr:\n{}",
            self.render_args(args),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        decode_output(output)
    }

    pub fn run_with_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> CommandResult {
        let output = self
            .command_with_env(args, extra_env)
            .output()
            .expect("run igloo-shell");
        assert!(
            output.status.success(),
            "command failed: {}\nstdout:\n{}\nstderr:\n{}",
            self.render_args(args),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        decode_output(output)
    }

    pub fn run_expect_failure(&self, args: &[&str], extra_env: &[(&str, &str)]) -> CommandResult {
        let output = self
            .command_with_env(args, extra_env)
            .output()
            .expect("run igloo-shell");
        assert!(
            !output.status.success(),
            "expected failure: {}\nstdout:\n{}\nstderr:\n{}",
            self.render_args(args),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        decode_output(output)
    }

    pub fn run_json(&self, args: &[&str]) -> Value {
        self.run(args).json()
    }

    pub fn run_json_with_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Value {
        self.run_with_env(args, extra_env).json()
    }

    pub fn start_relay(&mut self) {
        let log_path = self.root.join("relay.log");
        let log = fs::File::create(&log_path).expect("create relay log");
        let err = log.try_clone().expect("clone relay log");
        let host = "127.0.0.1";
        let port = self
            .relay_url
            .rsplit(':')
            .next()
            .expect("relay port")
            .to_string();
        let child = Command::new(&self.bin)
            .args(["dev", "relay", "--host", host, "--port", &port])
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn relay");
        self.relay_child = Some(child);
        let address = format!("{host}:{port}");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if TcpStream::connect(&address).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("timed out waiting for relay listener at {address}");
    }

    pub fn keygen(&self, threshold: u16, count: u16) {
        let material_dir = self.material_dir();
        fs::create_dir_all(&material_dir).expect("create material dir");
        self.run(&[
            "dev",
            "keygen",
            "--out-dir",
            path_arg(&material_dir),
            "--threshold",
            &threshold.to_string(),
            "--count",
            &count.to_string(),
            "--relay",
            self.relay_url(),
        ]);
    }

    pub fn set_relay_profile(&self, profile_id: &str) {
        self.run(&["relays", "set", profile_id, self.relay_url()]);
    }

    pub fn import_profile(&self, share_name: &str, label: &str, relay_profile: &str) -> Value {
        let label = self.unique_label(label);
        self.run_json_with_env(
            &[
                "profile",
                "import",
                "--group",
                path_arg(&self.material_dir().join("group.json")),
                "--share",
                path_arg(&self.material_dir().join(share_name)),
                "--label",
                &label,
                "--relay-profile",
                relay_profile,
            ],
            &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
        )
    }

    pub fn import_onboarding_package(
        &self,
        package_path: &Path,
        label: &str,
        relay_profile: &str,
        onboarding_password: &str,
    ) -> Value {
        let label = self.unique_label(label);
        self.run_json_with_env(
            &[
                "profile",
                "import",
                "--onboarding-package",
                path_arg(package_path),
                "--label",
                &label,
                "--relay-profile",
                relay_profile,
            ],
            &[
                ("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase"),
                ("IGLOO_SHELL_ONBOARDING_PASSWORD", onboarding_password),
            ],
        )
    }

    pub fn setup_onboarding_package(
        &self,
        package_path: &Path,
        label: &str,
        relay_profile: &str,
        onboarding_password: &str,
    ) -> Value {
        let label = self.unique_label(label);
        self.run_json_with_env(
            &[
                "setup",
                "--onboarding-package",
                path_arg(package_path),
                "--label",
                &label,
                "--relay-profile",
                relay_profile,
                "--start-daemon",
            ],
            &[
                ("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase"),
                ("IGLOO_SHELL_ONBOARDING_PASSWORD", onboarding_password),
            ],
        )
    }

    pub fn assemble_onboarding_package(
        &self,
        token: &str,
        share_name: &str,
        password: &str,
    ) -> String {
        self.run_with_env(
            &[
                "invite",
                "assemble",
                "--token",
                token,
                "--share",
                path_arg(&self.material_dir().join(share_name)),
                "--password-env",
                "IGLOO_SHELL_ONBOARDING_PASSWORD",
            ],
            &[("IGLOO_SHELL_ONBOARDING_PASSWORD", password)],
        )
        .stdout
        .trim()
        .to_string()
    }

    pub fn save_onboarding_package(&self, name: &str, package: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, package).expect("write onboarding package");
        path
    }

    pub fn start_daemon(&self, profile_id: &str) {
        self.run_daemon_lifecycle(&["daemon", "start", "--profile", profile_id]);
    }

    pub fn stop_daemon(&self, profile_id: &str) {
        let _ = self.run_with_env(
            &["daemon", "stop", "--profile", profile_id],
            &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
        );
    }

    pub fn restart_daemon(&self, profile_id: &str) {
        self.run_daemon_lifecycle(&["daemon", "restart", "--profile", profile_id]);
    }

    pub fn wait_for_runtime(&self, profile_id: &str, timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let output = self
                .command_with_env(
                    &["runtime", "status", "--profile", profile_id],
                    &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
                )
                .output()
                .expect("run runtime status");
            if output.status.success() {
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
        let log = fs::read_to_string(self.daemon_log_path(profile_id))
            .unwrap_or_else(|_| "<daemon log unavailable>".to_string());
        panic!("timed out waiting for runtime status for {profile_id}\ndaemon log:\n{log}");
    }

    pub fn wait_for_sign_ready(&self, profile_id: &str, timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let status = self.run_json_with_env(
                &["runtime", "status", "--profile", profile_id],
                &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
            );
            let readiness = status
                .get("readiness")
                .expect("runtime status readiness");
            let sign_ready = readiness
                .get("sign_ready")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let ecdh_ready = readiness
                .get("ecdh_ready")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if sign_ready && ecdh_ready {
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
        panic!("timed out waiting for sign/ecdh readiness for {profile_id}");
    }

    pub fn render_args(&self, args: &[&str]) -> String {
        format!("{} {}", self.bin.display(), args.join(" "))
    }

    pub fn list_profiles(&self) -> Value {
        self.run_json(&["profile", "list"])
    }

    fn command(&self, args: &[&str]) -> Command {
        self.command_with_env(args, &[])
    }

    fn command_with_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(&self.bin);
        command.args(args);
        command.env("XDG_CONFIG_HOME", self.config_home());
        command.env("XDG_DATA_HOME", self.data_home());
        command.env("XDG_STATE_HOME", self.state_home());
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command
    }

    fn unique_label(&self, label: &str) -> String {
        let short = &self.tag[..self.tag.len().min(8)];
        format!("{label}-{short}")
    }

    fn run_daemon_lifecycle(&self, args: &[&str]) {
        let mut last_stdout = String::new();
        let mut last_stderr = String::new();
        for _ in 0..3 {
            let output = self
                .command_with_env(args, &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")])
                .output()
                .expect("run daemon lifecycle command");
            last_stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            last_stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if output.status.success() {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }
        panic!(
            "command failed after retries: {}\nstdout:\n{}\nstderr:\n{}",
            self.render_args(args),
            last_stdout,
            last_stderr
        );
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let profiles = self.list_profiles();
        if let Some(items) = profiles.as_array() {
            for item in items {
                if let Some(profile_id) = item.get("id").and_then(Value::as_str) {
                    let _ = self
                        .command_with_env(
                            &["daemon", "stop", "--profile", profile_id],
                            &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
                        )
                        .output();
                }
            }
        }
        if let Some(child) = &mut self.relay_child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn decode_output(output: Output) -> CommandResult {
    CommandResult {
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    }
}

fn global_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn extract_profile_id(value: &Value) -> String {
    value
        .get("profile")
        .and_then(|profile| profile.get("id"))
        .and_then(Value::as_str)
        .or_else(|| value.get("id").and_then(Value::as_str))
        .map(ToString::to_string)
        .expect("extract profile id")
}

pub fn extract_token(value: &Value) -> String {
    value.get("token")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .expect("extract invite token")
}

pub fn path_arg(path: &Path) -> &str {
    path.to_str().expect("valid utf-8 path")
}
