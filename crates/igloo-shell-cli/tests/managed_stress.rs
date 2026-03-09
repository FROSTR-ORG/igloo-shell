mod support;

use support::TestHarness;

#[test]
#[ignore = "stress"]
fn managed_e2e_full_11_of_15() {
    let mut harness = TestHarness::new("managed-stress");
    harness.start_relay();
    harness.run(&[
        "dev",
        "e2e-full",
        "--out-dir",
        support::path_arg(&harness.root().join("stress-out")),
        "--relay",
        harness.relay_url(),
        "--threshold",
        "11",
        "--count",
        "15",
        "--sign-iterations",
        "20",
        "--ecdh-iterations",
        "20",
    ]);
}
