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

    // C.5: peer list talks to the running daemon over the control socket;
    // no profile passphrase is needed.
    let peers = harness.run_json(&["peer", "list", "--profile", &alice_id]);
    let peer = peers
        .as_array()
        .and_then(|items| items.first())
        .and_then(|entry| entry.get("pubkey"))
        .and_then(Value::as_str)
        .expect("peer pubkey")
        .to_string();

    let set_default = harness.run_json(&[
        "policy",
        "set-default-override",
        "--profile",
        &alice_id,
        "--direction",
        "request",
        "--method",
        "sign",
        "--value",
        "deny",
    ]);
    assert_eq!(
        set_default.get("restart_required"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        set_default
            .get("manifest")
            .and_then(|manifest| manifest.get("policy_overrides"))
            .and_then(|overrides| overrides.get("default_override"))
            .and_then(|policy| policy.get("request"))
            .and_then(|request| request.get("sign"))
            .and_then(Value::as_str),
        Some("deny")
    );

    harness.restart_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(20));

    // C.5: policy mutations write the manifest and call the daemon; no
    // profile passphrase is needed.
    let updated = harness.run_json(&[
        "policy",
        "set-peer-override",
        "--profile",
        &alice_id,
        &peer,
        "--direction",
        "respond",
        "--method",
        "sign",
        "--value",
        "deny",
    ]);
    assert_eq!(updated.get("updated"), Some(&Value::Bool(true)));
    assert_eq!(updated.get("persisted"), Some(&Value::Bool(true)));
    assert!(updated.get("result").is_some());

    // The `ask` disposition (interactive approval) round-trips through the CLI,
    // daemon, and persisted manifest like allow/deny.
    let asked = harness.run_json(&[
        "policy",
        "set-peer-override",
        "--profile",
        &alice_id,
        &peer,
        "--direction",
        "respond",
        "--method",
        "sign",
        "--value",
        "ask",
    ]);
    assert_eq!(asked.get("updated"), Some(&Value::Bool(true)));
    let asked_manifest = harness.run_json(&["profile", "show", &alice_id]);
    let asked_value = asked_manifest
        .get("policy_overrides")
        .and_then(|value| value.get("peer_overrides"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|entry| entry.get("policy_override"))
        .and_then(|policy| policy.get("respond"))
        .and_then(|respond| respond.get("sign"))
        .and_then(Value::as_str);
    assert_eq!(asked_value, Some("ask"));

    // Resolving an unknown approval id is a no-op success (the signer drops it).
    let resolved = harness.run_json(&[
        "runtime",
        "resolve-approval",
        "--profile",
        &alice_id,
        "no-such-approval",
        "--approved",
        "true",
    ]);
    assert_eq!(resolved.get("updated"), Some(&Value::Bool(true)));

    let cleared = harness.run_json(&["policy", "clear-peer", "--profile", &alice_id, &peer]);
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
            "set-default-override",
            "--profile",
            "missing",
            "--direction",
            "request",
            "--method",
            "sign",
            "--value",
            "maybe",
        ],
        &[],
    );
    assert!(failure.stderr.contains("invalid value"));
}
