#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SHELL_ROOT="${ROOT_DIR}/repos/igloo-shell"
BIFROST_ROOT="${ROOT_DIR}/repos/bifrost-rs"
ITERATIONS=25
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations)
      ITERATIONS="${2:?missing value for --iterations}"
      shift 2
      ;;
    --out)
      OUT="${2:?missing value for --out}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if ! [[ "${ITERATIONS}" =~ ^[0-9]+$ ]] || [[ "${ITERATIONS}" -lt 1 ]]; then
  echo "--iterations must be a positive integer" >&2
  exit 1
fi

if [[ -z "${OUT}" ]]; then
  OUT="dev/audit/work/evidence/ws-soak-$(date +%F-%H%M%S).txt"
fi

mkdir -p "$(dirname "${OUT}")"

run() {
  echo "$ $*"
  "$@"
}

run_with_retry() {
  local retries="$1"
  shift
  local attempt=1
  while true; do
    echo "$ $* (attempt ${attempt}/${retries})"
    if "$@"; then
      return 0
    fi
    if [[ "${attempt}" -ge "${retries}" ]]; then
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
}

{
  echo "ws soak started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "iterations: ${ITERATIONS}"

  for i in $(seq 1 "${ITERATIONS}"); do
    echo "--- bridge/signer forced-fault iteration ${i}/${ITERATIONS} ---"
  run cargo test --manifest-path "${BIFROST_ROOT}/Cargo.toml" -p bifrost-bridge-tokio --offline ecdh_round_fails_on_invalid_locked_peer_response
  run cargo test --manifest-path "${BIFROST_ROOT}/Cargo.toml" -p bifrost-bridge-tokio --offline outbound_queue_overflow_fails_round
  run cargo test --manifest-path "${BIFROST_ROOT}/Cargo.toml" -p bifrost-bridge-tokio --offline inbound_duplicate_event_is_processed_once
  done

  echo "--- codec/signer crypto regression ---"
  run cargo test --manifest-path "${BIFROST_ROOT}/Cargo.toml" -p bifrost-codec --offline bridge_envelope_rejects_empty_request_id
  run cargo test --manifest-path "${BIFROST_ROOT}/Cargo.toml" -p bifrost-signer --offline invalid_locked_peer_response_fails_round_terminally

  echo "--- managed-profile runtime stress regression ---"
  run_with_retry 3 cargo run --manifest-path "${SHELL_ROOT}/Cargo.toml" -p igloo-shell-cli --offline -- dev e2e-full --out-dir dev/data --relay ws://127.0.0.1:8194 --threshold 11 --count 15 --sign-iterations 20 --ecdh-iterations 20

  echo "ws soak completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee "${OUT}"
