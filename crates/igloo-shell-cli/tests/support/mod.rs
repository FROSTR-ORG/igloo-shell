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
    devtools_bin: PathBuf,
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
        let devtools_bin = ensure_devtools_bin();
        Self {
            root,
            bin,
            devtools_bin,
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

    pub fn encrypted_profiles_dir(&self) -> PathBuf {
        self.shell_data_dir().join("encrypted-profiles")
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

    pub fn run_for_a_bit_with_env(
        &self,
        args: &[&str],
        extra_env: &[(&str, &str)],
        duration: Duration,
    ) -> CommandResult {
        let mut command = self.command_with_env(args, extra_env);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn igloo-shell");
        thread::sleep(duration);
        let _ = child.kill();
        let output = child.wait_with_output().expect("wait for igloo-shell");
        decode_output(output)
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
        let child = Command::new(&self.devtools_bin)
            .args(["relay", "--host", host, "--port", &port])
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn bifrost-devtools relay");
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
        let output = Command::new(&self.devtools_bin)
            .args([
                "keygen",
                "--out-dir",
                path_arg(&material_dir),
                "--group-name",
                "Test Group",
                "--threshold",
                &threshold.to_string(),
                "--count",
                &count.to_string(),
                "--relay",
                self.relay_url(),
            ])
            .output()
            .expect("run bifrost-devtools keygen");
        assert!(
            output.status.success(),
            "keygen failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub fn set_relay_profile(&self, profile_id: &str) {
        self.run(&["relays", "set", profile_id, self.relay_url()]);
    }

    pub fn import_profile(&self, share_name: &str, label: &str, relay_profile: &str) -> Value {
        let label = self.unique_label(label);
        self.run_json_with_env(
            &[
                "import",
                "--group",
                path_arg(&self.material_dir().join("group.json")),
                "--share",
                path_arg(&self.material_dir().join(share_name)),
                "--label",
                &label,
                "--relay-profile",
                relay_profile,
                "--passphrase",
                "encrypted-profile-passphrase",
                "--json",
            ],
            &[],
        )
    }

    pub fn onboard(
        &self,
        package_path: &Path,
        label: &str,
        onboarding_secret: &str,
        passphrase: &str,
    ) -> Value {
        let label = self.unique_label(label);
        self.run_json(&[
            "onboard",
            path_arg(package_path),
            "--onboard-secret",
            onboarding_secret,
            "--passphrase",
            passphrase,
            "--json",
            "--label",
            &label,
        ])
    }

    pub fn onboard_inline(
        &self,
        package: &str,
        label: &str,
        onboarding_secret: &str,
        passphrase: &str,
    ) -> Value {
        let label = self.unique_label(label);
        self.run_json(&[
            "onboard",
            package,
            "--onboard-secret",
            onboarding_secret,
            "--passphrase",
            passphrase,
            "--json",
            "--label",
            &label,
        ])
    }

    pub fn onboard_with_secret_files(
        &self,
        package_path: &Path,
        label: &str,
        onboarding_secret_file: &Path,
        passphrase_file: &Path,
    ) -> Value {
        let label = self.unique_label(label);
        self.run_json(&[
            "onboard",
            path_arg(package_path),
            "--onboard-secret-file",
            path_arg(onboarding_secret_file),
            "--passphrase-file",
            path_arg(passphrase_file),
            "--json",
            "--label",
            &label,
        ])
    }

    pub fn rotate_key(
        &self,
        package_path: &Path,
        profile_id: &str,
        onboarding_secret: &str,
        passphrase: &str,
    ) -> Value {
        self.run_json(&[
            "rotate-key",
            path_arg(package_path),
            "--profile",
            profile_id,
            "--onboard-secret",
            onboarding_secret,
            "--passphrase",
            passphrase,
            "--json",
        ])
    }

    pub fn rotate_key_expect_failure(
        &self,
        package_path: &Path,
        profile_id: &str,
        onboarding_secret: &str,
        passphrase: &str,
    ) -> CommandResult {
        self.run_expect_failure(
            &[
                "rotate-key",
                path_arg(package_path),
                "--profile",
                profile_id,
                "--onboard-secret",
                onboarding_secret,
                "--passphrase",
                passphrase,
            ],
            &[],
        )
    }

    pub fn export_bfonboard_package(
        &self,
        profile_id: &str,
        share_name: &str,
        password: &str,
    ) -> String {
        let out_path = self
            .root
            .join(format!("{profile_id}-{share_name}.bfonboard"));
        self.run_with_env(
            &[
                "export",
                profile_id,
                "--format",
                "bfonboard",
                "--out",
                path_arg(&out_path),
                "--recipient-share",
                path_arg(&self.material_dir().join(share_name)),
                "--package-password-env",
                "IGLOO_SHELL_PACKAGE_PASSWORD",
            ],
            &[
                ("IGLOO_SHELL_PACKAGE_PASSWORD", password),
                (
                    "IGLOO_SHELL_PROFILE_PASSPHRASE",
                    "encrypted-profile-passphrase",
                ),
            ],
        );
        fs::read_to_string(&out_path)
            .expect("read bfonboard export")
            .trim()
            .to_string()
    }

    pub fn export_bfshare_package(&self, profile_id: &str, password: &str) -> String {
        let out_path = self.root.join(format!("{profile_id}.bfshare"));
        self.run_with_env(
            &[
                "export",
                profile_id,
                "--format",
                "bfshare",
                "--out",
                path_arg(&out_path),
                "--package-password-env",
                "IGLOO_SHELL_PACKAGE_PASSWORD",
            ],
            &[
                ("IGLOO_SHELL_PACKAGE_PASSWORD", password),
                (
                    "IGLOO_SHELL_PROFILE_PASSPHRASE",
                    "encrypted-profile-passphrase",
                ),
            ],
        );
        fs::read_to_string(&out_path)
            .expect("read bfshare export")
            .trim()
            .to_string()
    }

    pub fn export_bfprofile_package(&self, profile_id: &str, password: &str) -> String {
        let out_path = self.root.join(format!("{profile_id}.bfprofile"));
        self.run_with_env(
            &[
                "export",
                profile_id,
                "--format",
                "bfprofile",
                "--out",
                path_arg(&out_path),
                "--package-password-env",
                "IGLOO_SHELL_PACKAGE_PASSWORD",
            ],
            &[
                ("IGLOO_SHELL_PACKAGE_PASSWORD", password),
                (
                    "IGLOO_SHELL_PROFILE_PASSPHRASE",
                    "encrypted-profile-passphrase",
                ),
            ],
        );
        fs::read_to_string(&out_path)
            .expect("read bfprofile export")
            .trim()
            .to_string()
    }

    pub fn export_raw_profile(&self, profile_id: &str) -> PathBuf {
        let out_path = self.root.join(format!("{profile_id}.raw.json"));
        self.run_with_env(
            &[
                "export",
                profile_id,
                "--format",
                "raw",
                "--out",
                path_arg(&out_path),
            ],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        );
        out_path
    }

    pub fn save_onboarding_package(&self, name: &str, package: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, package).expect("write onboarding package");
        path
    }

    pub fn save_text_file(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("write text file");
        path
    }

    pub fn rotate_keyset_init(
        &self,
        profile_id: &str,
        threshold: u16,
        count: u16,
        workspace: &Path,
        source_packages: &[&Path],
    ) -> Value {
        let mut args = vec![
            "rotate-keyset".to_string(),
            "init".to_string(),
            "--profile".to_string(),
            profile_id.to_string(),
            "--threshold".to_string(),
            threshold.to_string(),
            "--count".to_string(),
            count.to_string(),
            "--workspace".to_string(),
            path_arg(workspace).to_string(),
            "--passphrase".to_string(),
            "encrypted-profile-passphrase".to_string(),
            "--json".to_string(),
        ];
        for package in source_packages {
            args.push("--source-bfshare".to_string());
            args.push(path_arg(package).to_string());
        }
        let argv = args.iter().map(String::as_str).collect::<Vec<_>>();
        self.run_json(&argv)
    }

    pub fn rotate_keyset_show(&self, workspace: &Path) -> Value {
        self.run_json(&[
            "rotate-keyset",
            "show",
            "--workspace",
            path_arg(workspace),
            "--json",
        ])
    }

    pub fn rotate_keyset_generate(
        &self,
        workspace: &Path,
        distribution_secret: &str,
        extra_env: &[(&str, &str)],
    ) -> Value {
        let mut env = vec![(
            "IGLOO_SHELL_PROFILE_PASSPHRASE",
            "encrypted-profile-passphrase",
        )];
        env.extend_from_slice(extra_env);
        self.run_json_with_env(
            &[
                "rotate-keyset",
                "generate",
                "--workspace",
                path_arg(workspace),
                "--passphrase",
                "encrypted-profile-passphrase",
                "--distribution-secret",
                distribution_secret,
                "--json",
            ],
            &env,
        )
    }

    pub fn start_daemon(&self, profile_id: &str) {
        self.run_daemon_lifecycle(&["daemon", "start", "--profile", profile_id]);
    }

    pub fn stop_daemon(&self, profile_id: &str) {
        let _ = self.run_with_env(
            &["daemon", "stop", "--profile", profile_id],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
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
                    &[(
                        "IGLOO_SHELL_PROFILE_PASSPHRASE",
                        "encrypted-profile-passphrase",
                    )],
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
            let sign = self.run_check(profile_id, "sign");
            let ecdh = self.run_check(profile_id, "ecdh");
            let sign_ready = sign.get("ready").and_then(Value::as_bool).unwrap_or(false);
            let ecdh_ready = ecdh.get("ready").and_then(Value::as_bool).unwrap_or(false);
            if sign_ready && ecdh_ready {
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
        panic!("timed out waiting for sign/ecdh readiness for {profile_id}");
    }

    pub fn run_check(&self, profile_id: &str, kind: &str) -> Value {
        self.run_json_with_env(
            &["check", kind, "--profile", profile_id],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        )
    }

    pub fn render_args(&self, args: &[&str]) -> String {
        format!("{} {}", self.bin.display(), args.join(" "))
    }

    pub fn list_profiles(&self) -> Value {
        self.run_json(&["profile", "list"])
    }

    pub fn show_profile(&self, profile_id: &str) -> Value {
        self.run_json(&["profile", "show", profile_id])
    }

    pub fn backup_profile(&self, profile_id: &str) -> Value {
        self.run_json_with_env(
            &[
                "profile",
                "backup",
                profile_id,
                "--passphrase-env",
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
            ],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        )
    }

    pub fn doctor_profile(&self, profile_id: &str) -> Value {
        self.run_json(&["profile", "doctor", profile_id])
    }

    pub fn remove_profile(&self, profile_id: &str) -> Value {
        self.run_json(&["profile", "remove", profile_id, "--yes"])
    }

    pub fn daemon_status(&self, profile_id: Option<&str>) -> Value {
        match profile_id {
            Some(profile_id) => self.run_json_with_env(
                &["daemon", "status", "--profile", profile_id],
                &[(
                    "IGLOO_SHELL_PROFILE_PASSPHRASE",
                    "encrypted-profile-passphrase",
                )],
            ),
            None => self.run_json(&["daemon", "status"]),
        }
    }

    pub fn daemon_logs(&self, profile_id: &str) -> Value {
        self.run_json(&["daemon", "logs", "--profile", profile_id])
    }

    pub fn runtime_status(&self, profile_id: &str) -> Value {
        self.run_json_with_env(
            &["runtime", "status", "--profile", profile_id],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        )
    }

    pub fn runtime_diagnostics(&self, profile_id: &str) -> Value {
        self.run_json_with_env(
            &["runtime", "diagnostics", "--profile", profile_id],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        )
    }

    pub fn runtime_ops(&self, profile_id: &str) -> Value {
        self.run_json_with_env(
            &["runtime", "ops", "--profile", profile_id],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        )
    }

    pub fn runtime_wipe_state(&self, profile_id: &str) -> Value {
        self.run_json_with_env(
            &["runtime", "wipe-state", "--profile", profile_id, "--yes"],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        )
    }

    pub fn relay_list(&self) -> Value {
        self.run_json(&["relays", "list"])
    }

    pub fn relay_set(&self, profile_id: &str, label: Option<&str>, relays: &[&str]) -> Value {
        let mut args = vec!["relays", "set", profile_id];
        if let Some(label) = label {
            args.push("--label");
            args.push(label);
        }
        args.extend(relays.iter().copied());
        self.run_json(&args)
    }

    pub fn relay_add(&self, profile_id: &str, relays: &[&str]) -> Value {
        let mut args = vec!["relays", "add", profile_id];
        args.extend(relays.iter().copied());
        self.run_json(&args)
    }

    pub fn relay_remove(&self, profile_id: &str, relays: &[&str]) -> Value {
        let mut args = vec!["relays", "remove", profile_id];
        args.extend(relays.iter().copied());
        self.run_json(&args)
    }

    pub fn relay_default(&self, profile_id: &str) -> Value {
        self.run_json(&["relays", "default", profile_id])
    }

    pub fn relay_test(&self, profile_id: Option<&str>) -> Value {
        match profile_id {
            Some(profile_id) => self.run_json(&["relays", "test", "--relay-profile", profile_id]),
            None => self.run_json(&["relays", "test"]),
        }
    }

    pub fn keys_convert(&self, from: &str, value: &str) -> Value {
        self.run_json(&["keys", "convert", "--from", from, "--value", value])
    }

    pub fn wait_for_profile_id_by_label(&self, label: &str, timeout: Duration) -> String {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let profiles = self.list_profiles();
            if let Some(profile_id) = profiles
                .as_array()
                .and_then(|items| {
                    items.iter().find(|item| {
                        item.get("label")
                            .and_then(Value::as_str)
                            .is_some_and(|candidate| candidate == label)
                    })
                })
                .and_then(|item| item.get("id"))
                .and_then(Value::as_str)
            {
                return profile_id.to_string();
            }
            thread::sleep(Duration::from_millis(200));
        }
        panic!("timed out waiting for profile label {label}");
    }

    pub fn wait_for_replaced_profile_id(
        &self,
        label: &str,
        previous_profile_id: &str,
        timeout: Duration,
    ) -> String {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let profiles = self.list_profiles();
            if let Some(profile_id) = profiles
                .as_array()
                .and_then(|items| {
                    items.iter().find(|item| {
                        item.get("label")
                            .and_then(Value::as_str)
                            .is_some_and(|candidate| candidate == label)
                            && item.get("id").and_then(Value::as_str) != Some(previous_profile_id)
                    })
                })
                .and_then(|item| item.get("id"))
                .and_then(Value::as_str)
            {
                return profile_id.to_string();
            }
            thread::sleep(Duration::from_millis(200));
        }
        panic!("timed out waiting for replacement profile label {label}");
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
                .command_with_env(
                    args,
                    &[(
                        "IGLOO_SHELL_PROFILE_PASSPHRASE",
                        "encrypted-profile-passphrase",
                    )],
                )
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
                            &[(
                                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                                "encrypted-profile-passphrase",
                            )],
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

fn ensure_devtools_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let infra_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("resolve infra root")
            .to_path_buf();
        let bifrost_root = infra_root.join("repos/bifrost-rs");
        let bin = bifrost_root.join("target/debug/bifrost-devtools");
        let status = Command::new("cargo")
            .args([
                "build",
                "--manifest-path",
                path_arg(&bifrost_root.join("Cargo.toml")),
                "-p",
                "bifrost-devtools",
                "--bin",
                "bifrost-devtools",
                "--offline",
            ])
            .status()
            .expect("build bifrost-devtools");
        assert!(status.success(), "failed to build bifrost-devtools");
        bin
    })
    .clone()
}

pub fn extract_profile_id(value: &Value) -> String {
    value
        .get("profile")
        .and_then(|profile| profile.get("id"))
        .or_else(|| {
            value
                .get("import")
                .and_then(|import| import.get("profile"))
                .and_then(|profile| profile.get("id"))
        })
        .and_then(Value::as_str)
        .or_else(|| value.get("id").and_then(Value::as_str))
        .map(ToString::to_string)
        .expect("extract profile id")
}

pub fn extract_profile_label(value: &Value) -> String {
    value
        .get("profile")
        .and_then(|profile| profile.get("label"))
        .or_else(|| {
            value
                .get("import")
                .and_then(|import| import.get("profile"))
                .and_then(|profile| profile.get("label"))
        })
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .expect("extract profile label")
}

pub fn extract_token(value: &Value) -> String {
    value
        .get("token")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .expect("extract daemon token")
}

pub fn path_arg(path: &Path) -> &str {
    path.to_str().expect("valid utf-8 path")
}
