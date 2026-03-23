mod support;

use std::time::Duration;

use serde_json::Value;
use support::{TestHarness, extract_profile_id};

#[test]
fn onboard_with_password_flag_creates_profile() {
    let mut harness = TestHarness::new("onboarding-import");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-bob.json", "invite-pass");
    let package_path = harness.save_onboarding_package("bob.onboarding", &package);

    let imported = harness.onboard(&package_path, "bob", "invite-pass", "vault-passphrase");
    let bob_id = extract_profile_id(&imported);
    let imported_payload = imported.get("import").expect("onboard import payload");
    let bob = imported_payload
        .get("profile")
        .expect("profile import payload");
    let diagnostics = imported_payload
        .get("diagnostics")
        .expect("onboarding diagnostics");
    let expected_next = format!("igloo-shell profile load {bob_id}");

    assert_eq!(
        imported
            .get("next")
            .and_then(|next| next.get("load"))
            .and_then(Value::as_str),
        Some(expected_next.as_str())
    );
    assert!(bob.get("relay_profile").is_some());
    assert!(
        diagnostics
            .get("validation_passed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    assert_eq!(
        harness.list_profiles().as_array().map(|items| items.len()),
        Some(2)
    );

    harness.start_daemon(&bob_id);
    harness.wait_for_runtime(&bob_id, Duration::from_secs(20));
    harness.wait_for_sign_ready(&bob_id, Duration::from_secs(20));
}

#[test]
fn profile_load_without_runtime_start_prints_next_commands() {
    let mut harness = TestHarness::new("profile-load-summary");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);

    let result = harness.run(&[
        "profile",
        "load",
        &alice_id,
        "--vault-secret",
        "vault-passphrase",
    ]);

    assert!(result.stdout.contains("Profile loaded:"));
    assert!(result.stdout.contains("Vault unlock succeeded."));
    assert!(
        result
            .stdout
            .contains(&format!("igloo-shell profile load {alice_id} --start"))
    );
    assert!(
        result
            .stdout
            .contains(&format!("igloo-shell profile load {alice_id} --daemon"))
    );
    assert!(
        result
            .stdout
            .contains(&format!("igloo-shell daemon status --profile {alice_id}"))
    );

    let status = harness.run_expect_failure(
        &["daemon", "status", "--profile", &alice_id],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    assert!(status.stderr.contains("daemon metadata is not present"));
}

#[test]
fn profile_load_with_daemon_starts_background_runtime() {
    let mut harness = TestHarness::new("profile-load-daemon");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);

    let result = harness.run(&[
        "profile",
        "load",
        &alice_id,
        "--vault-secret",
        "vault-passphrase",
        "--daemon",
    ]);

    assert!(result.stdout.contains("Daemon"));
    assert!(
        result
            .stdout
            .contains(&format!("igloo-shell runtime status --profile {alice_id}"))
    );
    assert!(
        result
            .stdout
            .contains(&format!("igloo-shell peer list --profile {alice_id}"))
    );
    assert!(
        result
            .stdout
            .contains(&format!("igloo-shell policy show --profile {alice_id}"))
    );
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));
}

#[test]
fn import_non_json_prints_next_commands_and_exits() {
    let mut harness = TestHarness::new("import-non-json");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let label = "alice-import";
    let result = harness.run(&[
        "import",
        "--group",
        support::path_arg(&harness.material_dir().join("group.json")),
        "--share",
        support::path_arg(&harness.material_dir().join("share-alice.json")),
        "--label",
        label,
        "--relay-profile",
        "local",
        "--vault-secret",
        "vault-passphrase",
    ]);

    assert!(result.stdout.contains("Import complete."));
    assert!(result.stdout.contains("Next commands:"));
    assert!(result.stdout.contains("igloo-shell profile load"));
}

#[test]
fn import_with_start_attaches_to_daemon_log() {
    let mut harness = TestHarness::new("import-start");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let _result = harness.run_for_a_bit_with_env(
        &[
            "import",
            "--group",
            support::path_arg(&harness.material_dir().join("group.json")),
            "--share",
            support::path_arg(&harness.material_dir().join("share-alice.json")),
            "--label",
            "alice-start",
            "--relay-profile",
            "local",
            "--vault-secret",
            "vault-passphrase",
            "--start",
        ],
        &[],
        Duration::from_secs(10),
    );

    let profiles = harness.list_profiles();
    let profile_id = profiles
        .as_array()
        .and_then(|items| {
            items.iter().find(|item| {
                item.get("label")
                    .and_then(Value::as_str)
                    .is_some_and(|label| label == "alice-start")
            })
        })
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .expect("imported profile id")
        .to_string();
    harness.wait_for_runtime(&profile_id, Duration::from_secs(20));
}

#[test]
fn recover_non_json_prints_next_commands_and_exits() {
    let mut harness = TestHarness::new("recover-non-json");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.run_with_env(
        &[
            "profile",
            "backup",
            &alice_id,
            "--vault-passphrase-env",
            "IGLOO_SHELL_VAULT_PASSPHRASE",
        ],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let share = harness.export_bfshare_package(&alice_id, "recover-pass");
    let share_path = harness.save_onboarding_package("alice.bfshare", &share);

    let result = harness.run(&[
        "recover",
        support::path_arg(&share_path),
        "--label",
        "alice-recovered",
        "--package-secret",
        "recover-pass",
        "--vault-secret",
        "vault-passphrase",
    ]);

    assert!(result.stdout.contains("Recovery complete."));
    assert!(result.stdout.contains("Next commands:"));
    assert!(result.stdout.contains("igloo-shell profile load"));
}

#[test]
fn recover_with_start_attaches_to_daemon_log() {
    let mut harness = TestHarness::new("recover-start");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.run_with_env(
        &[
            "profile",
            "backup",
            &alice_id,
            "--vault-passphrase-env",
            "IGLOO_SHELL_VAULT_PASSPHRASE",
        ],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let share = harness.export_bfshare_package(&alice_id, "recover-pass");
    let share_path = harness.save_onboarding_package("alice-start.bfshare", &share);

    let _result = harness.run_for_a_bit_with_env(
        &[
            "recover",
            support::path_arg(&share_path),
            "--label",
            "alice-recover-start",
            "--package-secret",
            "recover-pass",
            "--vault-secret",
            "vault-passphrase",
            "--start",
        ],
        &[],
        Duration::from_secs(6),
    );

    let profiles = harness.list_profiles();
    let profile_id = profiles
        .as_array()
        .and_then(|items| {
            items.iter().find(|item| {
                item.get("label")
                    .and_then(Value::as_str)
                    .is_some_and(|label| label == "alice-recover-start")
            })
        })
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .expect("recovered profile id")
        .to_string();
    harness.wait_for_runtime(&profile_id, Duration::from_secs(20));
}

#[test]
fn onboard_non_json_with_daemon_starts_background_runtime() {
    let mut harness = TestHarness::new("onboard-non-json-daemon");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-bob.json", "invite-pass");
    let package_path = harness.save_onboarding_package("bob.onboarding", &package);

    let result = harness.run(&[
        "onboard",
        support::path_arg(&package_path),
        "--label",
        "bob-daemon",
        "--onboard-secret",
        "invite-pass",
        "--vault-secret",
        "vault-passphrase",
        "--daemon",
    ]);

    assert!(result.stdout.contains("Onboarding complete."));
    assert!(result.stdout.contains("Daemon"));

    let profiles = harness.list_profiles();
    let bob_id = profiles
        .as_array()
        .and_then(|items| {
            items.iter().find(|item| {
                item.get("label")
                    .and_then(Value::as_str)
                    .is_some_and(|label| label == "bob-daemon")
            })
        })
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .expect("bob profile id")
        .to_string();
    harness.wait_for_runtime(&bob_id, Duration::from_secs(20));
}

#[test]
fn onboard_with_start_attaches_to_daemon_log() {
    let mut harness = TestHarness::new("onboard-start");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-bob.json", "invite-pass");
    let package_path = harness.save_onboarding_package("bob-start.onboarding", &package);

    let _result = harness.run_for_a_bit_with_env(
        &[
            "onboard",
            support::path_arg(&package_path),
            "--label",
            "bob-start",
            "--onboard-secret",
            "invite-pass",
            "--vault-secret",
            "vault-passphrase",
            "--start",
        ],
        &[],
        Duration::from_secs(10),
    );

    let profile_id =
        harness.wait_for_profile_id_by_label("bob-start", Duration::from_secs(20));
    harness.wait_for_runtime(&profile_id, Duration::from_secs(20));
}

#[test]
fn keygen_non_json_prints_artifact_summary_and_exits() {
    let mut harness = TestHarness::new("keygen-non-json");
    harness.start_relay();

    let result = harness.run(&[
        "keygen",
        "--keyset-name",
        "demo-keyset",
        "--threshold",
        "2",
        "--count",
        "3",
        "--member-index",
        "1",
        "--label",
        "alice-keygen",
        "--relay-url",
        harness.relay_url(),
        "--vault-secret",
        "vault-passphrase",
        "--distribution-secret",
        "dist-passphrase",
    ]);

    assert!(result.stdout.contains("Keyset generated."));
    assert!(result.stdout.contains("Local profile created."));
    assert!(result.stdout.contains("Next commands:"));
    assert_eq!(
        harness.list_profiles().as_array().map(|items| items.len()),
        Some(1)
    );
}

#[test]
fn check_commands_report_onboard_sign_and_ecdh_readiness() {
    let mut harness = TestHarness::new("check-commands");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);

    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let onboard = harness.run_check(&alice_id, "onboard");
    assert_eq!(onboard.get("kind").and_then(Value::as_str), Some("onboard"));
    assert_eq!(onboard.get("ready").and_then(Value::as_bool), Some(true));
    assert!(
        onboard
            .get("relay_connected_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    let sign = harness.run_check(&alice_id, "sign");
    assert_eq!(sign.get("kind").and_then(Value::as_str), Some("sign"));
    assert_eq!(sign.get("ready").and_then(Value::as_bool), Some(false));
    assert!(
        sign.get("reasons_not_ready")
            .and_then(Value::as_array)
            .is_some_and(|reasons| reasons
                .iter()
                .any(|reason| reason.as_str() == Some("insufficient_signing_peers")))
    );

    let ecdh = harness.run_check(&alice_id, "ecdh");
    assert_eq!(ecdh.get("kind").and_then(Value::as_str), Some("ecdh"));
    assert_eq!(ecdh.get("ready").and_then(Value::as_bool), Some(false));
    assert!(
        ecdh.get("reasons_not_ready")
            .and_then(Value::as_array)
            .is_some_and(|reasons| reasons
                .iter()
                .any(|reason| reason.as_str() == Some("insufficient_ecdh_peers")))
    );
}

#[test]
fn deleted_runtime_readiness_commands_no_longer_parse() {
    let harness = TestHarness::new("deleted-readiness-commands");
    let failure = harness.run_expect_failure(&["runtime", "readiness", "--profile", "demo"], &[]);
    assert!(failure.stderr.contains("unrecognized subcommand"));
}

#[test]
fn onboard_supports_secret_file_input() {
    let mut harness = TestHarness::new("onboard-password-file");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-carol.json", "setup-pass");
    let package_path = harness.save_onboarding_package("carol.onboarding", &package);
    let onboard_secret_path =
        harness.save_onboarding_package("carol.onboard-secret", "setup-pass\n");
    let vault_secret_path =
        harness.save_onboarding_package("carol.vault-secret", "vault-passphrase\n");

    let imported = harness.onboard_with_secret_files(
        &package_path,
        "carol",
        &onboard_secret_path,
        &vault_secret_path,
    );
    let carol_id = extract_profile_id(&imported);
    let onboard_payload = imported.get("import").expect("onboard import payload");
    assert!(
        onboard_payload
            .get("profile")
            .and_then(|profile| profile.get("relay_profile"))
            .is_some()
    );

    harness.start_daemon(&carol_id);
    harness.wait_for_runtime(&carol_id, Duration::from_secs(20));
}

#[test]
fn onboard_requires_label_on_non_tty() {
    let mut harness = TestHarness::new("onboard-missing-label");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-dave.json", "invite-pass");
    let package_path = harness.save_onboarding_package("eve.onboarding", &package);

    let failure = harness.run_expect_failure(
        &[
            "onboard",
            support::path_arg(&package_path),
            "--onboard-secret",
            "invite-pass",
            "--vault-secret",
            "vault-passphrase",
            "--json",
        ],
        &[],
    );

    assert!(failure.stderr.contains("--label"));
}

#[test]
fn onboard_accepts_inline_package_payload() {
    let mut harness = TestHarness::new("onboard-inline");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-dave.json", "inline-pass");

    let imported =
        harness.onboard_inline(&package, "dave-inline", "inline-pass", "vault-passphrase");
    let profile_id = extract_profile_id(&imported);

    harness.start_daemon(&profile_id);
    harness.wait_for_runtime(&profile_id, Duration::from_secs(20));
}

#[test]
fn onboard_without_onboard_secret_flags_fails_on_non_tty() {
    let mut harness = TestHarness::new("onboard-no-password");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-carol.json", "prompt-pass");
    let package_path = harness.save_onboarding_package("carol-prompt.onboarding", &package);

    let failure = harness.run_expect_failure(
        &[
            "onboard",
            support::path_arg(&package_path),
            "--vault-secret",
            "vault-passphrase",
            "--label",
            "carol-prompt",
        ],
        &[],
    );

    assert!(
        failure
            .stderr
            .contains("--onboard-secret / --onboard-secret-file")
    );
}

#[test]
fn onboard_without_vault_secret_flags_fails_on_non_tty() {
    let mut harness = TestHarness::new("onboard-no-vault-secret");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-dave.json", "vault-pass");
    let package_path = harness.save_onboarding_package("dave-vault-prompt.onboarding", &package);

    let failure = harness.run_expect_failure(
        &[
            "onboard",
            support::path_arg(&package_path),
            "--onboard-secret",
            "vault-pass",
            "--label",
            "dave-vault-prompt",
        ],
        &[],
    );

    assert!(
        failure
            .stderr
            .contains("--vault-secret / --vault-secret-file")
    );
}

#[test]
fn onboarding_import_with_wrong_password_leaves_no_profiles_or_vault_records() {
    let mut harness = TestHarness::new("onboarding-wrong-password");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-dave.json", "correct-pass");
    let package_path = harness.save_onboarding_package("dave.onboarding", &package);

    let failure = harness.run_expect_failure(
        &[
            "onboard",
            support::path_arg(&package_path),
            "--onboard-secret",
            "wrong-pass",
            "--vault-secret",
            "vault-passphrase",
            "--label",
            "dave",
        ],
        &[],
    );

    assert!(failure.stderr.contains("decode bfonboard package"));
    assert_eq!(
        harness.list_profiles().as_array().map(|items| items.len()),
        Some(1)
    );
    let vault_entries = std::fs::read_dir(harness.vault_dir())
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(vault_entries, 2);
}

#[test]
fn managed_runtime_e2e_covers_ping_onboard_sign_and_ecdh() {
    let mut harness = TestHarness::new("managed-runtime");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let bob = harness.import_profile("share-bob.json", "bob", "local");
    let carol = harness.import_profile("share-carol.json", "carol", "local");

    let alice_id = extract_profile_id(&alice);
    let bob_id = extract_profile_id(&bob);
    let carol_id = extract_profile_id(&carol);

    harness.start_daemon(&alice_id);
    harness.start_daemon(&bob_id);
    harness.start_daemon(&carol_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));
    harness.wait_for_runtime(&bob_id, Duration::from_secs(20));
    harness.wait_for_runtime(&carol_id, Duration::from_secs(20));

    let peers = harness.run_json_with_env(
        &["peer", "list", "--profile", &alice_id],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let peer_pubkeys = peers
        .as_array()
        .expect("peer list array")
        .iter()
        .filter_map(|entry| entry.get("pubkey").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(peer_pubkeys.len(), 2);

    for peer in &peer_pubkeys {
        harness.run_json_with_env(
            &["peer", "ping", "--profile", &alice_id, peer],
            &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
        );
        harness.run_json_with_env(
            &["peer", "onboard", "--profile", &alice_id, peer],
            &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
        );
    }
    harness.wait_for_sign_ready(&alice_id, Duration::from_secs(20));

    let sign = harness.run_json_with_env(
        &[
            "runtime",
            "sign",
            "--profile",
            &alice_id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let signature = sign
        .get("signatures_hex")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .expect("signature hex");
    assert_eq!(signature.len(), 128);

    let ecdh = harness.run_json_with_env(
        &["runtime", "ecdh", "--profile", &alice_id, &peer_pubkeys[0]],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let secret = ecdh
        .get("shared_secret_hex32")
        .and_then(Value::as_str)
        .expect("shared secret");
    assert_eq!(secret.len(), 64);
}
