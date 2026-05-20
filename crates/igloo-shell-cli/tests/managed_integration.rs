mod support;

use std::fs;
use std::time::Duration;

use serde_json::Value;
use support::{TestHarness, extract_profile_id, extract_profile_label};

fn group_public_key_for_profile(harness: &TestHarness, profile_id: &str) -> String {
    let shown = harness.show_profile(profile_id);
    let group_ref = shown
        .get("group_ref")
        .and_then(Value::as_str)
        .expect("group ref");
    let group: Value =
        serde_json::from_str(&fs::read_to_string(group_ref).expect("read group package"))
            .expect("parse group package");
    match group.get("group_pk") {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Array(group_pk)) => group_pk
            .iter()
            .map(|byte| {
                format!(
                    "{:02x}",
                    byte.as_u64().expect("group public key byte") as u8
                )
            })
            .collect::<String>(),
        _ => panic!("group public key bytes"),
    }
}

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

    let imported = harness.onboard(
        &package_path,
        "bob",
        "invite-pass",
        "encrypted-profile-passphrase",
    );
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
fn exported_bfonboard_round_trips_through_shell_onboard() {
    let mut harness = TestHarness::new("onboarding-roundtrip");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package = harness.export_bfonboard_package(&alice_id, "share-carol.json", "roundtrip-pass");
    let package_path = harness.save_onboarding_package("carol-roundtrip.onboarding", &package);

    let imported = harness.onboard(
        &package_path,
        "carol-roundtrip",
        "roundtrip-pass",
        "encrypted-profile-passphrase",
    );
    let profile_id = extract_profile_id(&imported);
    assert_ne!(profile_id, alice_id);

    harness.start_daemon(&profile_id);
    harness.wait_for_runtime(&profile_id, Duration::from_secs(20));
}

#[test]
fn rotate_keyset_init_and_generate_replace_local_profile_and_emit_bfonboard_packages() {
    let mut harness = TestHarness::new("rotate-keyset-generate");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    let alice_label = extract_profile_label(&alice);
    let bob = harness.import_profile("share-bob.json", "bob", "local");
    let bob_id = extract_profile_id(&bob);
    harness.backup_profile(&alice_id);
    harness.backup_profile(&bob_id);

    let alice_bfshare = harness.export_bfshare_package(&alice_id, "alice-rotate-pass");
    let bob_bfshare = harness.export_bfshare_package(&bob_id, "bob-rotate-pass");
    let alice_bfshare_path =
        harness.save_onboarding_package("alice-rotate.bfshare", &alice_bfshare);
    let bob_bfshare_path = harness.save_onboarding_package("bob-rotate.bfshare", &bob_bfshare);
    let workspace = harness.root().join("rotation-workspace");

    let init = harness.rotate_keyset_init(
        &alice_id,
        2,
        4,
        &workspace,
        &[alice_bfshare_path.as_path(), bob_bfshare_path.as_path()],
    );
    let show = harness.rotate_keyset_show(&workspace);
    let status = show.get("status").expect("rotation workspace status");
    assert_eq!(
        status
            .get("source_packages_present")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        status
            .get("source_packages_required")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        status
            .get("local_target_member_index")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        status.get("remote_target_count").and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        init.get("workspace").and_then(Value::as_str),
        Some(workspace.display().to_string().as_str())
    );

    let manifest_path = workspace.join("rotation.json");
    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read rotation manifest"))
            .expect("parse rotation manifest");
    let sources = manifest
        .get_mut("source_packages")
        .and_then(Value::as_array_mut)
        .expect("rotation source packages");
    sources[0]["package_secret_env"] = Value::String("ROTATE_SRC_ALICE".to_string());
    sources[1]["package_secret_env"] = Value::String("ROTATE_SRC_BOB".to_string());
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize rotation manifest"),
    )
    .expect("write rotation manifest");

    let generated = harness.rotate_keyset_generate(
        &workspace,
        "rotate-distribution-pass",
        &[
            ("ROTATE_SRC_ALICE", "alice-rotate-pass"),
            ("ROTATE_SRC_BOB", "bob-rotate-pass"),
        ],
    );

    let rotation = generated
        .get("rotation_generate")
        .expect("rotation generate payload");
    let replaced_profile_id = rotation
        .get("replaced_profile_id")
        .and_then(Value::as_str)
        .expect("replaced profile id");
    let new_profile = rotation.get("profile").expect("new local profile");
    let new_profile_id = new_profile
        .get("id")
        .and_then(Value::as_str)
        .expect("new local profile id");
    assert_eq!(replaced_profile_id, alice_id);
    assert_ne!(new_profile_id, alice_id);
    assert_eq!(
        new_profile.get("label").and_then(Value::as_str),
        Some(alice_label.as_str())
    );
    assert_ne!(
        rotation.get("source_group_id").and_then(Value::as_str),
        rotation.get("next_group_id").and_then(Value::as_str)
    );

    let profiles = harness.list_profiles();
    let ids = profiles
        .as_array()
        .expect("profile list")
        .iter()
        .filter_map(|profile| profile.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(!ids.contains(&alice_id.as_str()));
    assert!(ids.contains(&new_profile_id));
    assert!(ids.contains(&bob_id.as_str()));

    let packages = rotation
        .get("generated_packages")
        .and_then(Value::as_array)
        .expect("generated packages");
    assert_eq!(packages.len(), 3);
    harness.start_daemon(new_profile_id);
    harness.wait_for_runtime(new_profile_id, Duration::from_secs(20));
    let rotated_group_pk = group_public_key_for_profile(&harness, new_profile_id);
    let mut onboard_package_path = None;
    let mut rotate_package_path = None;
    for package in packages {
        let path = package
            .get("path")
            .and_then(Value::as_str)
            .expect("generated package path");
        assert!(
            std::path::Path::new(path).is_file(),
            "missing generated package: {path}"
        );
        match package.get("member_index").and_then(Value::as_u64) {
            Some(2) => rotate_package_path = Some(path.to_string()),
            Some(3) => onboard_package_path = Some(path.to_string()),
            _ => {}
        }
    }

    let onboard_path = onboard_package_path.expect("member 3 onboarding package");
    let onboarded = harness.onboard(
        std::path::Path::new(&onboard_path),
        "rotated-carol",
        "rotate-distribution-pass",
        "encrypted-profile-passphrase",
    );
    let onboarded_id = extract_profile_id(&onboarded);
    harness.start_daemon(&onboarded_id);
    harness.wait_for_runtime(&onboarded_id, Duration::from_secs(20));
    assert_eq!(
        group_public_key_for_profile(&harness, &onboarded_id),
        rotated_group_pk.clone()
    );

    let rotate_path = rotate_package_path.expect("member 2 rotation package");
    let rotated_bob = harness.rotate_key(
        std::path::Path::new(&rotate_path),
        &bob_id,
        "rotate-distribution-pass",
        "encrypted-profile-passphrase",
    );
    let rotated_bob_id = extract_profile_id(&rotated_bob);
    assert_ne!(rotated_bob_id, bob_id);
    harness.start_daemon(&rotated_bob_id);
    harness.wait_for_runtime(&rotated_bob_id, Duration::from_secs(20));
    assert_eq!(
        group_public_key_for_profile(&harness, &rotated_bob_id),
        rotated_group_pk
    );
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
        "--passphrase",
        "encrypted-profile-passphrase",
    ]);

    assert!(result.stdout.contains("Profile loaded:"));
    assert!(result.stdout.contains("Passphrase accepted."));
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

    // C.5: daemon status reads daemon.json only; no passphrase needed.
    let status = harness.run_expect_failure(&["daemon", "status", "--profile", &alice_id], &[]);
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
        "--passphrase",
        "encrypted-profile-passphrase",
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
        "--passphrase",
        "encrypted-profile-passphrase",
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

    // C.6: with Bucket B's Argon2id defaults (m=256MB / t=4) running once
    // in the parent and once in the spawned daemon, the import + start
    // sequence routinely takes >10s on contended hosts. Give the
    // attached-mode runner enough wall clock to reach a bound socket.
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
            "--passphrase",
            "encrypted-profile-passphrase",
            "--start",
        ],
        &[],
        Duration::from_secs(30),
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
    harness.wait_for_runtime(&profile_id, Duration::from_secs(30));
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
            "--passphrase-env",
            "BACKUP_PASS",
        ],
        &[("BACKUP_PASS", "encrypted-profile-passphrase")],
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
        "--passphrase",
        "encrypted-profile-passphrase",
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
            "--passphrase-env",
            "BACKUP_PASS",
        ],
        &[("BACKUP_PASS", "encrypted-profile-passphrase")],
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
            "--passphrase",
            "encrypted-profile-passphrase",
            "--start",
        ],
        // C.6: Argon2id runs twice (parent + spawned daemon) — give the
        // attached-mode runner enough wall clock to reach a bound socket.
        &[],
        Duration::from_secs(30),
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
fn rotate_key_replaces_profile_with_bfonboard() {
    let mut harness = TestHarness::new("rotate-key-json");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    let alice_label = extract_profile_label(&alice);
    let bob = harness.import_profile("share-bob.json", "bob", "local");
    let bob_id = extract_profile_id(&bob);
    harness.start_daemon(&bob_id);
    harness.wait_for_runtime(&bob_id, Duration::from_secs(20));
    let package = harness.export_bfonboard_package(&bob_id, "share-carol.json", "rotate-pass");
    let package_path = harness.save_onboarding_package("alice-rotate.onboarding", &package);

    let rotated = harness.rotate_key(
        &package_path,
        &alice_id,
        "rotate-pass",
        "encrypted-profile-passphrase",
    );
    let new_profile_id = extract_profile_id(&rotated);
    let expected_load = format!("igloo-shell profile load {new_profile_id}");

    assert_ne!(new_profile_id, alice_id);
    assert_eq!(
        rotated
            .get("rotation_update")
            .and_then(|value| value.get("replaced_profile_id"))
            .and_then(Value::as_str),
        Some(alice_id.as_str())
    );
    assert_eq!(
        rotated
            .get("next")
            .and_then(|value| value.get("load"))
            .and_then(Value::as_str),
        Some(expected_load.as_str())
    );

    let profiles = harness.list_profiles();
    let items = profiles.as_array().expect("profile array");
    assert_eq!(items.len(), 2);
    let rotated = items
        .iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(new_profile_id.as_str()))
        .expect("rotated profile");
    assert_eq!(
        rotated.get("label").and_then(Value::as_str),
        Some(alice_label.as_str())
    );
}

#[test]
fn rotate_key_with_daemon_starts_replacement_runtime() {
    let mut harness = TestHarness::new("rotate-key-daemon");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    let alice_label = extract_profile_label(&alice);
    let bob = harness.import_profile("share-bob.json", "bob", "local");
    let bob_id = extract_profile_id(&bob);
    harness.start_daemon(&bob_id);
    harness.wait_for_runtime(&bob_id, Duration::from_secs(20));
    let package = harness.export_bfonboard_package(&bob_id, "share-carol.json", "rotate-pass");
    let package_path = harness.save_onboarding_package("alice-rotate-daemon.onboarding", &package);

    let result = harness.run(&[
        "rotate-key",
        support::path_arg(&package_path),
        "--profile",
        &alice_id,
        "--onboard-secret",
        "rotate-pass",
        "--passphrase",
        "encrypted-profile-passphrase",
        "--daemon",
    ]);

    assert!(result.stdout.contains("Rotation update complete."));
    assert!(
        result
            .stdout
            .contains("igloo-shell runtime status --profile")
    );

    let new_profile_id =
        harness.wait_for_replaced_profile_id(&alice_label, &alice_id, Duration::from_secs(20));
    assert_ne!(new_profile_id, alice_id);
    harness.wait_for_runtime(&new_profile_id, Duration::from_secs(20));
}

#[test]
fn rotate_key_with_start_attaches_to_daemon_log() {
    let mut harness = TestHarness::new("rotate-key-start");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    let alice_label = extract_profile_label(&alice);
    let bob = harness.import_profile("share-bob.json", "bob", "local");
    let bob_id = extract_profile_id(&bob);
    harness.start_daemon(&bob_id);
    harness.wait_for_runtime(&bob_id, Duration::from_secs(20));
    let package = harness.export_bfonboard_package(&bob_id, "share-carol.json", "rotate-pass");
    let package_path = harness.save_onboarding_package("alice-rotate-start.onboarding", &package);

    let _result = harness.run_for_a_bit_with_env(
        &[
            "rotate-key",
            support::path_arg(&package_path),
            "--profile",
            &alice_id,
            "--onboard-secret",
            "rotate-pass",
            "--passphrase",
            "encrypted-profile-passphrase",
            "--start",
        ],
        // C.6: Argon2id runs twice (parent + spawned daemon) — give the
        // attached-mode runner enough wall clock to reach a bound socket.
        &[],
        Duration::from_secs(30),
    );

    let new_profile_id =
        harness.wait_for_replaced_profile_id(&alice_label, &alice_id, Duration::from_secs(30));
    assert_ne!(new_profile_id, alice_id);
    // C.6: the rotated profile's daemon must run Argon2id again during
    // signer-state init; bump the readiness timeout accordingly.
    harness.wait_for_runtime(&new_profile_id, Duration::from_secs(45));
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
        "--passphrase",
        "encrypted-profile-passphrase",
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
            "--passphrase",
            "encrypted-profile-passphrase",
            "--start",
        ],
        // C.6: Argon2id runs twice (parent + spawned daemon) — give the
        // attached-mode runner enough wall clock to reach a bound socket.
        &[],
        Duration::from_secs(30),
    );

    let profile_id = harness.wait_for_profile_id_by_label("bob-start", Duration::from_secs(20));
    harness.wait_for_runtime(&profile_id, Duration::from_secs(20));
}

#[test]
fn keygen_non_json_prints_artifact_summary_and_exits() {
    let mut harness = TestHarness::new("keygen-non-json");
    harness.start_relay();

    let result = harness.run(&[
        "keygen",
        "--group-name",
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
        "--passphrase",
        "encrypted-profile-passphrase",
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
    let passphrase_path = harness.save_onboarding_package(
        "carol.encrypted-profile-secret",
        "encrypted-profile-passphrase\n",
    );

    let imported = harness.onboard_with_secret_files(
        &package_path,
        "carol",
        &onboard_secret_path,
        &passphrase_path,
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
            "--passphrase",
            "encrypted-profile-passphrase",
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

    let imported = harness.onboard_inline(
        &package,
        "dave-inline",
        "inline-pass",
        "encrypted-profile-passphrase",
    );
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
            "--passphrase",
            "encrypted-profile-passphrase",
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
fn onboard_without_passphrase_flags_fails_on_non_tty() {
    let mut harness = TestHarness::new("onboard-no-encrypted-profile-secret");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let package =
        harness.export_bfonboard_package(&alice_id, "share-dave.json", "encrypted-profile-pass");
    let package_path =
        harness.save_onboarding_package("dave-encrypted-profile-prompt.onboarding", &package);

    let failure = harness.run_expect_failure(
        &[
            "onboard",
            support::path_arg(&package_path),
            "--onboard-secret",
            "encrypted-profile-pass",
            "--label",
            "dave-encrypted-profile-prompt",
        ],
        &[],
    );

    assert!(failure.stderr.contains("--passphrase / --passphrase-file"));
}

#[test]
fn onboarding_import_with_wrong_password_leaves_no_profiles_or_encrypted_profiles() {
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
            "--passphrase",
            "encrypted-profile-passphrase",
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
    let vault_entries = std::fs::read_dir(harness.encrypted_profiles_dir())
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

    // C.5: peer / runtime subcommands talk to the running daemon over
    // the control socket — no profile passphrase needed.
    let peers = harness.run_json(&["peer", "list", "--profile", &alice_id]);
    let peer_pubkeys = peers
        .as_array()
        .expect("peer list array")
        .iter()
        .filter_map(|entry| entry.get("pubkey").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(peer_pubkeys.len(), 2);

    for peer in &peer_pubkeys {
        harness.run_json(&["peer", "ping", "--profile", &alice_id, peer]);
        harness.run_json(&["peer", "onboard", "--profile", &alice_id, peer]);
    }
    harness.wait_for_sign_ready(&alice_id, Duration::from_secs(20));

    let sign = harness.run_json(&[
        "runtime",
        "sign",
        "--profile",
        &alice_id,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]);
    let signature = sign
        .get("signatures_hex")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .expect("signature hex");
    assert_eq!(signature.len(), 128);

    let ecdh = harness.run_json(&["runtime", "ecdh", "--profile", &alice_id, &peer_pubkeys[0]]);
    let secret = ecdh
        .get("shared_secret_hex32")
        .and_then(Value::as_str)
        .expect("shared secret");
    assert_eq!(secret.len(), 64);
}
