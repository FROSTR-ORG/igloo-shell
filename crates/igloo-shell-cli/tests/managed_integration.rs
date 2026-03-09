mod support;

use std::time::Duration;

use serde_json::Value;
use support::{TestHarness, extract_profile_id, extract_token};

#[test]
fn onboarding_package_import_creates_profile_and_starts_runtime() {
    let mut harness = TestHarness::new("onboarding-import");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let invite = harness.run_json_with_env(
        &["invite", "create", "--profile", &alice_id, "--label", "bob-onboarding"],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let token = extract_token(&invite);
    let package = harness.assemble_onboarding_package(&token, "share-bob.json", "invite-pass");
    let package_path = harness.save_onboarding_package("bob.onboarding", &package);

    let imported =
        harness.import_onboarding_package(&package_path, "bob", "local", "invite-pass");
    let bob_id = extract_profile_id(&imported);
    let bob = imported.get("profile").expect("profile import payload");
    let diagnostics = imported
        .get("diagnostics")
        .expect("onboarding diagnostics");

    assert_eq!(bob.get("relay_profile"), Some(&Value::String("local".to_string())));
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
fn setup_onboarding_package_starts_daemon_and_reuses_existing_relay_profile() {
    let mut harness = TestHarness::new("setup-onboarding");
    harness.start_relay();
    harness.keygen(2, 4);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let invite = harness.run_json_with_env(
        &["invite", "create", "--profile", &alice_id, "--label", "carol-onboarding"],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let token = extract_token(&invite);
    let package = harness.assemble_onboarding_package(&token, "share-carol.json", "setup-pass");
    let package_path = harness.save_onboarding_package("carol.onboarding", &package);

    let setup =
        harness.setup_onboarding_package(&package_path, "carol", "local", "setup-pass");
    let imported = setup.get("import").expect("setup import payload");
    let carol_id = extract_profile_id(imported);

    assert_eq!(setup.get("daemon_started"), Some(&Value::Bool(true)));
    assert_eq!(
        imported
            .get("profile")
            .and_then(|profile| profile.get("relay_profile")),
        Some(&Value::String("local".to_string()))
    );

    harness.wait_for_runtime(&carol_id, Duration::from_secs(20));
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

    let invite = harness.run_json_with_env(
        &["invite", "create", "--profile", &alice_id, "--label", "dave-onboarding"],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let token = extract_token(&invite);
    let package = harness.assemble_onboarding_package(&token, "share-dave.json", "correct-pass");
    let package_path = harness.save_onboarding_package("dave.onboarding", &package);

    let failure = harness.run_expect_failure(
        &[
            "profile",
            "import",
            "--onboarding-package",
            support::path_arg(&package_path),
            "--label",
            "dave",
            "--relay-profile",
            "local",
        ],
        &[
            ("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase"),
            ("IGLOO_SHELL_ONBOARDING_PASSWORD", "wrong-pass"),
        ],
    );

    assert!(failure.stderr.contains("decode onboarding package"));
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
fn managed_runtime_e2e_covers_ping_onboard_sign_ecdh_and_invites() {
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

    let invite = harness.run_json_with_env(
        &["invite", "create", "--profile", &alice_id, "--label", "managed-runtime"],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let token = extract_token(&invite);
    assert!(!token.is_empty());

    let invite_list = harness.run_json_with_env(
        &["invite", "list", "--profile", &alice_id],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let challenge = invite_list
        .as_array()
        .and_then(|items| items.first())
        .and_then(|entry| entry.get("challenge_hex"))
        .and_then(Value::as_str)
        .expect("invite challenge")
        .to_string();
    harness.run_json_with_env(
        &["invite", "show", "--profile", &alice_id, &challenge],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let revoked = harness.run_json_with_env(
        &["invite", "revoke", "--profile", &alice_id, &challenge],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    assert_eq!(revoked.get("revoked"), Some(&Value::Bool(true)));
}
