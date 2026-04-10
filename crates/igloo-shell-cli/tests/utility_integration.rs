mod support;

use std::fs;
use std::time::Duration;

use serde_json::Value;
use support::{TestHarness, extract_profile_id};

#[test]
fn export_formats_write_expected_artifacts_and_validate_required_flags() {
    let mut harness = TestHarness::new("utility-export");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);

    let raw_path = harness.export_raw_profile(&alice_id);
    assert!(raw_path.is_dir());
    let entries = fs::read_dir(&raw_path)
        .expect("read raw export dir")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(entries.iter().any(|entry| entry == "group.json"));
    assert!(
        entries
            .iter()
            .any(|entry| entry.starts_with("share-") && entry.ends_with(".json"))
    );

    let bfprofile = harness.export_bfprofile_package(&alice_id, "profile-pass");
    assert!(!bfprofile.is_empty());

    let bfshare = harness.export_bfshare_package(&alice_id, "share-pass");
    assert!(!bfshare.is_empty());

    let bfonboard = harness.export_bfonboard_package(&alice_id, "share-bob.json", "onboard-pass");
    assert!(!bfonboard.is_empty());

    let missing_password = harness.run_expect_failure(
        &[
            "export",
            &alice_id,
            "--format",
            "bfprofile",
            "--out",
            support::path_arg(&harness.root().join("missing-password.bfprofile")),
        ],
        &[(
            "IGLOO_SHELL_PROFILE_PASSPHRASE",
            "encrypted-profile-passphrase",
        )],
    );
    assert!(missing_password.stderr.contains("package password"));

    let missing_recipient = harness.run_expect_failure(
        &[
            "export",
            &alice_id,
            "--format",
            "bfonboard",
            "--out",
            support::path_arg(&harness.root().join("missing-recipient.bfonboard")),
            "--package-password-env",
            "IGLOO_SHELL_PACKAGE_PASSWORD",
        ],
        &[
            ("IGLOO_SHELL_PACKAGE_PASSWORD", "onboard-pass"),
            (
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            ),
        ],
    );
    assert!(
        missing_recipient
            .stderr
            .contains("--recipient-share is required")
    );

    let invalid_format = harness.run_expect_failure(
        &[
            "export",
            &alice_id,
            "--format",
            "bogus",
            "--out",
            support::path_arg(&harness.root().join("bogus.out")),
        ],
        &[(
            "IGLOO_SHELL_PROFILE_PASSPHRASE",
            "encrypted-profile-passphrase",
        )],
    );
    assert!(
        invalid_format
            .stderr
            .contains("unsupported profile export format")
    );
}

#[test]
fn profile_commands_cover_list_show_doctor_backup_and_remove() {
    let mut harness = TestHarness::new("utility-profile");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);

    let listed = harness.list_profiles();
    assert_eq!(listed.as_array().map(|items| items.len()), Some(1));

    let shown = harness.show_profile(&alice_id);
    assert_eq!(
        shown.get("id").and_then(Value::as_str),
        Some(alice_id.as_str())
    );

    let doctor = harness.doctor_profile(&alice_id);
    assert_eq!(
        doctor.get("profile_id").and_then(Value::as_str),
        Some(alice_id.as_str())
    );
    assert_eq!(
        doctor.get("group_present").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        doctor.get("relay_profile_exists").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        doctor.get("share_managed").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        doctor
            .get("encrypted_profile_exists")
            .and_then(Value::as_bool),
        Some(true)
    );

    let backup = harness.backup_profile(&alice_id);
    assert_eq!(
        backup.get("profile_id").and_then(Value::as_str),
        Some(alice_id.as_str())
    );
    assert!(backup.get("event_id").and_then(Value::as_str).is_some());

    let removed = harness.remove_profile(&alice_id);
    assert_eq!(removed.get("removed").and_then(Value::as_bool), Some(true));
    assert_eq!(
        harness.list_profiles().as_array().map(|items| items.len()),
        Some(0)
    );
}

#[test]
fn daemon_and_runtime_commands_cover_status_logs_restart_and_wipe_state() {
    let mut harness = TestHarness::new("utility-daemon-runtime");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let daemon_status = harness.daemon_status(Some(&alice_id));
    assert_eq!(
        daemon_status.get("profile").and_then(Value::as_str),
        Some(alice_id.as_str())
    );
    assert!(daemon_status.get("metadata").is_some());
    assert!(daemon_status.get("runtime").is_some());

    let all_statuses = harness.daemon_status(None);
    assert!(all_statuses.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("profile").and_then(Value::as_str) == Some(alice_id.as_str()))
    }));

    let logs = harness.daemon_logs(&alice_id);
    let log_path = logs
        .get("log_path")
        .and_then(Value::as_str)
        .expect("daemon log path");
    assert!(std::path::Path::new(log_path).exists());

    let diagnostics = harness.runtime_diagnostics(&alice_id);
    assert!(diagnostics.is_object());

    let ops = harness.runtime_ops(&alice_id);
    assert_eq!(
        ops.get("profile").and_then(Value::as_str),
        Some(alice_id.as_str())
    );
    assert!(ops.get("runtime_metadata").is_some());

    let missing_yes = harness.run_expect_failure(
        &["runtime", "wipe-state", "--profile", &alice_id],
        &[(
            "IGLOO_SHELL_PROFILE_PASSPHRASE",
            "encrypted-profile-passphrase",
        )],
    );
    assert!(
        missing_yes
            .stderr
            .contains("runtime wipe-state requires --yes")
    );

    let wiped = harness.runtime_wipe_state(&alice_id);
    assert!(wiped.is_object());

    harness.stop_daemon(&alice_id);
    let stopped = harness.run_expect_failure(
        &["runtime", "status", "--profile", &alice_id],
        &[(
            "IGLOO_SHELL_PROFILE_PASSPHRASE",
            "encrypted-profile-passphrase",
        )],
    );
    assert!(stopped.stderr.contains("daemon"));

    harness.restart_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));
    let restarted = harness.runtime_status(&alice_id);
    assert!(restarted.is_object());
}

#[test]
fn check_commands_fail_cleanly_after_daemon_stop() {
    let mut harness = TestHarness::new("utility-check-offline");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let onboard = harness.run_check(&alice_id, "onboard");
    assert_eq!(onboard.get("kind").and_then(Value::as_str), Some("onboard"));

    harness.stop_daemon(&alice_id);

    for kind in ["onboard", "sign", "ecdh"] {
        let failure = harness.run_json_with_env(
            &["check", kind, "--profile", &alice_id],
            &[(
                "IGLOO_SHELL_PROFILE_PASSPHRASE",
                "encrypted-profile-passphrase",
            )],
        );
        assert!(
            failure.get("ready").and_then(Value::as_bool) == Some(false),
            "expected check {kind} to report not-ready after daemon stop: {failure:?}"
        );
        assert!(
            failure
                .get("reasons_not_ready")
                .and_then(Value::as_array)
                .is_some_and(|reasons| reasons
                    .iter()
                    .any(|reason| reason.as_str() == Some("daemon_unreachable"))),
            "expected daemon_unreachable reason for check {kind}: {failure:?}"
        );
        assert!(
            failure
                .get("details")
                .and_then(|details| details.get("daemon_error"))
                .and_then(Value::as_str)
                .is_some_and(|message| message.contains("daemon metadata")),
            "expected daemon metadata error details for check {kind}: {failure:?}"
        );
    }
}

#[test]
fn relay_commands_mutate_profiles_and_report_connectivity() {
    let mut harness = TestHarness::new("utility-relays");
    harness.start_relay();

    let listed = harness.relay_set(
        "local",
        Some("Local Relay"),
        &[harness.relay_url(), "ws://127.0.0.1:65534"],
    );
    assert!(
        listed
            .get("profiles")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|item| {
                item.get("id").and_then(Value::as_str) == Some("local")
                    && item
                        .get("relays")
                        .and_then(Value::as_array)
                        .is_some_and(|relays| {
                            relays
                                .iter()
                                .any(|relay| relay.as_str() == Some(harness.relay_url()))
                        })
            }))
    );

    let updated = harness.relay_add("local", &["ws://127.0.0.1:65535"]);
    let local = updated
        .get("profiles")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Value::as_str) == Some("local"))
        })
        .expect("local relay profile");
    assert!(
        local
            .get("relays")
            .and_then(Value::as_array)
            .is_some_and(|relays| relays.len() >= 3)
    );

    let removed = harness.relay_remove("local", &["ws://127.0.0.1:65535"]);
    let local = removed
        .get("profiles")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Value::as_str) == Some("local"))
        })
        .expect("local relay profile after remove");
    assert!(
        local
            .get("relays")
            .and_then(Value::as_array)
            .is_some_and(|relays| relays
                .iter()
                .all(|relay| relay.as_str() != Some("ws://127.0.0.1:65535")))
    );

    harness.relay_set("alt", Some("Alt Relay"), &[harness.relay_url()]);
    let defaults = harness.relay_default("alt");
    assert_eq!(
        defaults
            .get("default_relay_profile_id")
            .and_then(Value::as_str),
        Some("alt")
    );

    let tested = harness.relay_test(Some("alt"));
    assert_eq!(
        tested.get("relay_profile_id").and_then(Value::as_str),
        Some("alt")
    );
    assert!(
        tested
            .get("relays")
            .and_then(Value::as_array)
            .is_some_and(|relays| relays
                .iter()
                .any(|relay| relay.get("ok").and_then(Value::as_bool) == Some(true)))
    );

    let relay_list = harness.relay_list();
    assert!(
        relay_list
            .get("profiles")
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() >= 2)
    );
}

#[test]
fn keys_convert_covers_valid_and_invalid_input() {
    let harness = TestHarness::new("utility-keys");
    let secret_hex = "1111111111111111111111111111111111111111111111111111111111111111";

    let converted = harness.keys_convert("hex-private", secret_hex);
    assert_eq!(
        converted
            .get("input")
            .and_then(|value| value.get("kind"))
            .and_then(Value::as_str),
        Some("hex-private")
    );
    assert!(
        converted
            .get("outputs")
            .and_then(|value| value.get("nsec"))
            .and_then(Value::as_str)
            .is_some()
    );

    let invalid = harness.run_expect_failure(
        &["keys", "convert", "--from", "bogus", "--value", "abc"],
        &[],
    );
    assert!(invalid.stderr.contains("unsupported key input kind"));
}

#[test]
fn rotate_key_rejects_wrong_secret_invalid_package_and_mismatched_group() {
    let mut harness = TestHarness::new("utility-rotate-key-negative");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    let bob = harness.import_profile("share-bob.json", "bob", "local");
    let bob_id = extract_profile_id(&bob);
    harness.start_daemon(&bob_id);
    harness.wait_for_runtime(&bob_id, Duration::from_secs(20));

    let valid_package =
        harness.export_bfonboard_package(&bob_id, "share-carol.json", "rotate-pass");
    let valid_path = harness.save_onboarding_package("rotate-valid.bfonboard", &valid_package);

    let wrong_secret = harness.rotate_key_expect_failure(
        &valid_path,
        &alice_id,
        "wrong-pass",
        "encrypted-profile-passphrase",
    );
    assert!(wrong_secret.stderr.contains("decrypt"));

    let invalid_path =
        harness.save_onboarding_package("invalid-package.bfonboard", "not-a-package");
    let invalid_package = harness.rotate_key_expect_failure(
        &invalid_path,
        &alice_id,
        "rotate-pass",
        "encrypted-profile-passphrase",
    );
    assert!(
        invalid_package.stderr.contains("package") || invalid_package.stderr.contains("decode")
    );

    harness.keygen(2, 3);
    let mallory = harness.import_profile("share-alice.json", "mallory", "local");
    let mallory_id = extract_profile_id(&mallory);
    harness.start_daemon(&mallory_id);
    harness.wait_for_runtime(&mallory_id, Duration::from_secs(20));
    let mismatched_package =
        harness.export_bfonboard_package(&mallory_id, "share-bob.json", "mismatch-pass");
    let mismatched_path =
        harness.save_onboarding_package("rotate-mismatch.bfonboard", &mismatched_package);

    let mismatched = harness.rotate_key_expect_failure(
        &mismatched_path,
        &alice_id,
        "mismatch-pass",
        "encrypted-profile-passphrase",
    );
    assert!(
        mismatched
            .stderr
            .contains("rotation update does not match the selected profile group public key")
    );
}
