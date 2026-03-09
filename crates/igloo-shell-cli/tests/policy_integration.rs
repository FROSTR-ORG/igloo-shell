mod support;

use std::time::Duration;

use serde_json::Value;
use support::{TestHarness, extract_profile_id};

#[test]
fn live_policy_commands_persist_and_update_runtime() {
    let mut harness = TestHarness::new("policy-runtime");
    harness.start_relay();
    harness.keygen(2, 3);
    harness.set_relay_profile("local");

    let alice = harness.import_profile("share-alice.json", "alice", "local");
    let bob = harness.import_profile("share-bob.json", "bob", "local");
    let carol = harness.import_profile("share-carol.json", "carol", "local");

    let alice_id = extract_profile_id(&alice);
    harness.start_daemon(&alice_id);
    harness.start_daemon(&extract_profile_id(&bob));
    harness.start_daemon(&extract_profile_id(&carol));
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let peers = harness.run_json_with_env(
        &["peer", "list", "--profile", &alice_id],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let peer = peers
        .as_array()
        .and_then(|items| items.first())
        .and_then(|entry| entry.get("pubkey"))
        .and_then(Value::as_str)
        .expect("peer pubkey")
        .to_string();

    let set_default = harness.run_json(
        &[
            "policy",
            "set-default",
            "--profile",
            &alice_id,
            "--send",
            "false",
            "--receive",
            "true",
        ],
    );
    assert_eq!(set_default.get("restart_required"), Some(&Value::Bool(true)));

    harness.restart_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    let updated = harness.run_json_with_env(
        &[
            "policy",
            "set-peer",
            "--profile",
            &alice_id,
            &peer,
            "--send",
            "true",
            "--receive",
            "false",
        ],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    assert_eq!(updated.get("updated"), Some(&Value::Bool(true)));
    assert_eq!(updated.get("persisted"), Some(&Value::Bool(true)));

    let live = harness.run_json_with_env(
        &["policy", "show", "--profile", &alice_id],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    let live_policy = live
        .get(&peer)
        .expect("live peer policy");
    assert_eq!(
        live_policy
            .get("request")
            .and_then(|request| request.get("sign"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        live_policy
            .get("respond")
            .and_then(|respond| respond.get("sign"))
            .and_then(Value::as_bool),
        Some(false)
    );

    let manifest = harness.run_json(&["profile", "show", &alice_id]);
    assert_eq!(
        manifest
            .get("policy_overrides")
            .and_then(|overrides| overrides.get("default_policy"))
            .and_then(|policy| policy.get("request"))
            .and_then(|request| request.get("sign"))
            .and_then(Value::as_bool),
        Some(false)
    );

    let cleared = harness.run_json_with_env(
        &["policy", "clear-peer", "--profile", &alice_id, &peer],
        &[("IGLOO_SHELL_VAULT_PASSPHRASE", "vault-passphrase")],
    );
    assert_eq!(cleared.get("updated"), Some(&Value::Bool(true)));
    let manifest = harness.run_json(&["profile", "show", &alice_id]);
    let overrides = manifest
        .get("policy_overrides")
        .and_then(|value| value.get("peer_overrides"))
        .and_then(Value::as_array)
        .expect("peer overrides");
    assert!(overrides.is_empty());
}

#[test]
fn invalid_policy_bool_is_rejected() {
    let harness = TestHarness::new("policy-invalid");
    let failure = harness.run_expect_failure(
        &[
            "policy",
            "set-default",
            "--profile",
            "missing",
            "--send",
            "maybe",
            "--receive",
            "true",
        ],
        &[],
    );
    assert!(failure.stderr.contains("expected boolean value"));
}
