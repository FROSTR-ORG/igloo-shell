//! Full two-daemon approval round-trip: an `ask`-gated inbound sign parks on the
//! responder, and `runtime resolve-approval` either denies it (the initiator's sign
//! fails) or approves it (the initiator's sign completes with a verifiable signature).
//!
//! This is the Rust/shell analog of `test/igloo-pwa/specs/approval-queue.spec.ts`. It
//! upgrades the prior smoke-level coverage (`policy_integration.rs`: `ask` persists;
//! resolve-approval on an unknown id is a no-op) to the real parked-request flow.

mod support;

use std::time::{Duration, Instant};

use serde_json::Value;
use support::{TestHarness, extract_profile_id};

/// Poll the responder's `pending_approvals` until a parked `sign` request appears,
/// returning its `request_id`.
fn wait_for_parked_sign(harness: &TestHarness, profile_id: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let status = harness.run_json(&["runtime", "status", "--profile", profile_id]);
        let parked = status
            .get("pending_approvals")
            .and_then(Value::as_array)
            .and_then(|approvals| {
                approvals
                    .iter()
                    .find(|a| a.get("method").and_then(Value::as_str) == Some("sign"))
            })
            .and_then(|a| a.get("request_id").and_then(Value::as_str))
            .map(str::to_string);
        if let Some(request_id) = parked {
            return request_id;
        }
        assert!(
            Instant::now() < deadline,
            "no parked sign approval within {timeout:?}; status:\n{status:#}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The responder's view of its only peer (the initiator) in a 2-of-2 group.
fn only_peer_pubkey(harness: &TestHarness, profile_id: &str) -> String {
    let peers = harness.run_json(&["peer", "list", "--profile", profile_id]);
    peers
        .as_array()
        .and_then(|items| items.first())
        .and_then(|peer| peer.get("pubkey"))
        .and_then(Value::as_str)
        .expect("responder should know the initiator peer")
        .to_string()
}

#[test]
fn approval_round_trip_denies_then_approves() {
    let mut harness = TestHarness::new("approval-roundtrip");
    harness.start_relay();
    harness.keygen(2, 2);
    harness.set_relay_profile("local");

    // Alice holds one share and invites bob to the other. The onboarding handshake
    // (not a bare dual-import) is what seeds mutual peer presence + nonce exchange, so
    // both daemons reach sign-readiness — mirroring `onboard_with_password_flag_*`.
    let alice_id =
        extract_profile_id(&harness.import_profile("share-alice.json", "alice", "local"));
    harness.start_daemon(&alice_id);
    harness.wait_for_runtime(&alice_id, Duration::from_secs(30));

    let package = harness.export_bfonboard_package(&alice_id, "share-bob.json", "invite-pass");
    let package_path = harness.save_onboarding_package("bob.onboarding", &package);
    let bob_id = extract_profile_id(&harness.onboard(
        &package_path,
        "bob",
        "invite-pass",
        "encrypted-profile-passphrase",
    ));
    harness.start_daemon(&bob_id);
    harness.wait_for_runtime(&bob_id, Duration::from_secs(30));

    harness.wait_for_sign_ready(&bob_id, Duration::from_secs(60));
    harness.wait_for_sign_ready(&alice_id, Duration::from_secs(60));

    // Bob gates inbound sign requests from alice on an operator decision.
    let alice_pubkey = only_peer_pubkey(&harness, &bob_id);
    harness.run_json(&[
        "policy",
        "set-peer-override",
        "--profile",
        &bob_id,
        &alice_pubkey,
        "--direction",
        "respond",
        "--method",
        "sign",
        "--value",
        "ask",
    ]);

    let message_hex = "11".repeat(32);

    // --- Deny: the parked request is rejected, so alice's (blocking) sign fails. ---
    std::thread::scope(|scope| {
        let signer = scope.spawn(|| {
            harness.run_expect_failure(
                &["runtime", "sign", "--profile", &alice_id, &message_hex],
                &[],
            )
        });
        let request_id = wait_for_parked_sign(&harness, &bob_id, Duration::from_secs(30));
        harness.run_json(&[
            "runtime",
            "resolve-approval",
            "--profile",
            &bob_id,
            &request_id,
            "--approved",
            "false",
        ]);
        // `run_expect_failure` already asserts the non-zero exit; join to surface panics.
        let _ = signer.join().expect("deny: sign thread panicked");
    });

    // --- Approve: the parked request is replayed, so alice's sign completes. ---
    let signed = std::thread::scope(|scope| {
        let signer =
            scope.spawn(|| harness.run(&["runtime", "sign", "--profile", &alice_id, &message_hex]));
        let request_id = wait_for_parked_sign(&harness, &bob_id, Duration::from_secs(30));
        harness.run_json(&[
            "runtime",
            "resolve-approval",
            "--profile",
            &bob_id,
            &request_id,
            "--approved",
            "true",
        ]);
        signer.join().expect("approve: sign thread panicked").json()
    });

    // A completed sign returns verified Schnorr signatures (the signer core verifies
    // the aggregate against the group key before returning).
    let signatures = signed
        .get("signatures_hex")
        .and_then(Value::as_array)
        .expect("sign result should carry signatures_hex");
    assert!(!signatures.is_empty(), "expected at least one signature");
    for signature in signatures {
        let hex = signature.as_str().expect("signature hex");
        assert_eq!(
            hex.len(),
            128,
            "expected a 64-byte Schnorr signature: {hex}"
        );
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "signature is not hex: {hex}"
        );
    }

    harness.stop_daemon(&alice_id);
    harness.stop_daemon(&bob_id);
}
