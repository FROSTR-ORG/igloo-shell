#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIFROST_MANIFEST="${ROOT_DIR}/../bifrost-rs/Cargo.toml"
WORK_DIR="${IGLOO_SHELL_DEVNET_DIR:-${ROOT_DIR}/.tmp/devnet}"
XDG_CONFIG_HOME="${WORK_DIR}/config"
XDG_DATA_HOME="${WORK_DIR}/data"
XDG_STATE_HOME="${WORK_DIR}/state"
MATERIAL_DIR="${WORK_DIR}/material"
LOG_DIR="${WORK_DIR}/logs"
PID_FILE="${WORK_DIR}/relay.env"
PROFILE_FILE="${WORK_DIR}/profiles.env"
RELAY_HOST="${RELAY_HOST:-127.0.0.1}"
RELAY_PORT="${RELAY_PORT:-8194}"
RELAY_URL="ws://${RELAY_HOST}:${RELAY_PORT}"
VAULT_PASSPHRASE="${IGLOO_SHELL_VAULT_PASSPHRASE:-devnet-passphrase}"

mkdir -p "${WORK_DIR}" "${LOG_DIR}"

usage() {
  cat <<USAGE
Usage: scripts/devnet.sh <command>

Commands:
  gen                Generate dev material, relay profile, and managed profiles
  start              Start relay + 3 profile daemons (alice/bob/carol)
  start-responders   Start relay + responder daemons only (bob/carol)
  stop               Stop managed profile daemons + relay
  status             Show relay and daemon status
  smoke              Run a managed-profile smoke flow and stop everything

Environment:
  IGLOO_SHELL_DEVNET_DIR   Override the generated devnet working directory
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

shell_cmd() {
  cargo run -p igloo-shell-cli --offline -- "$@"
}

devtools_cmd() {
  cargo run --manifest-path "${BIFROST_MANIFEST}" -p bifrost-devtools --offline -- "$@"
}

managed_shell_cmd() {
  env \
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
    XDG_DATA_HOME="${XDG_DATA_HOME}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    IGLOO_SHELL_VAULT_PASSPHRASE="${VAULT_PASSPHRASE}" \
    cargo run -p igloo-shell-cli --offline -- "$@"
}

parse_json_field() {
  local field="$1"
  sed -n "s/^[[:space:]]*\"${field}\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

parse_json_pubkeys() {
  sed -n 's/^[[:space:]]*"pubkey":[[:space:]]*"\([^"]*\)".*/\1/p'
}

write_profiles_file() {
  cat >"${PROFILE_FILE}" <<EOF
ALICE_PROFILE_ID=${ALICE_PROFILE_ID}
BOB_PROFILE_ID=${BOB_PROFILE_ID}
CAROL_PROFILE_ID=${CAROL_PROFILE_ID}
EOF
}

load_profiles() {
  if [[ ! -f "${PROFILE_FILE}" ]]; then
    echo "error: managed profiles not found; run scripts/devnet.sh gen first" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${PROFILE_FILE}"
}

ensure_profiles() {
  if [[ ! -f "${PROFILE_FILE}" ]]; then
    run_gen
  else
    load_profiles
  fi
}

import_profile() {
  local label="$1"
  local share_path="${MATERIAL_DIR}/share-${label}.json"
  local output
  output="$(
    managed_shell_cmd import \
      --group "${MATERIAL_DIR}/group.json" \
      --share "${share_path}" \
      --label "${label}" \
      --relay-profile local \
      --vault-secret "${VAULT_PASSPHRASE}" \
      --json
  )"
  printf '%s\n' "${output}" | parse_json_field "id"
}

run_gen() {
  need_cmd cargo

  rm -rf "${WORK_DIR}"
  mkdir -p "${WORK_DIR}" "${MATERIAL_DIR}" "${LOG_DIR}"

  devtools_cmd keygen \
    --out-dir "${MATERIAL_DIR}" \
    --threshold 2 \
    --count 4 \
    --relay "${RELAY_URL}" >/dev/null

  managed_shell_cmd relays set local "${RELAY_URL}" >/dev/null

  ALICE_PROFILE_ID="$(import_profile "alice")"
  BOB_PROFILE_ID="$(import_profile "bob")"
  CAROL_PROFILE_ID="$(import_profile "carol")"

  if [[ -z "${ALICE_PROFILE_ID}" || -z "${BOB_PROFILE_ID}" || -z "${CAROL_PROFILE_ID}" ]]; then
    echo "error: failed to import managed profiles" >&2
    exit 1
  fi

  write_profiles_file

  echo "generated managed devnet profiles"
  echo "alice=${ALICE_PROFILE_ID}"
  echo "bob=${BOB_PROFILE_ID}"
  echo "carol=${CAROL_PROFILE_ID}"
}

start_relay() {
  local existing
  existing="$(pgrep -f "bifrost-devtools.*relay.*${RELAY_PORT}" | head -n 1 || true)"
  if [[ -n "${existing}" ]]; then
    cat >"${PID_FILE}" <<EOF
RELAY_PID=${existing}
RELAY_OWNED=0
EOF
    echo "relay already running on ${RELAY_PORT}"
    return
  fi

  devtools_cmd relay --host "${RELAY_HOST}" --port "${RELAY_PORT}" >"${LOG_DIR}/relay.log" 2>&1 &
  local relay_pid=$!
  cat >"${PID_FILE}" <<EOF
RELAY_PID=${relay_pid}
RELAY_OWNED=1
EOF
  echo "started relay pid=${relay_pid}"
}

wait_for_runtime() {
  local profile_id="$1"
  local attempts="${2:-10}"
  local try
  for ((try = 1; try <= attempts; try++)); do
    if managed_shell_cmd runtime status --profile "${profile_id}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_profile_daemon() {
  local label="$1"
  local profile_id="$2"
  managed_shell_cmd daemon start --profile "${profile_id}" >/dev/null
  if ! wait_for_runtime "${profile_id}" 20; then
    echo "error: ${label} daemon did not become queryable" >&2
    exit 1
  fi
  echo "started ${label} daemon (${profile_id})"
}

run_start() {
  need_cmd cargo
  ensure_profiles
  start_relay
  sleep 1
  start_profile_daemon "alice" "${ALICE_PROFILE_ID}"
  start_profile_daemon "bob" "${BOB_PROFILE_ID}"
  start_profile_daemon "carol" "${CAROL_PROFILE_ID}"
  echo "devnet started"
}

run_start_responders() {
  need_cmd cargo
  ensure_profiles
  start_relay
  sleep 1
  start_profile_daemon "bob" "${BOB_PROFILE_ID}"
  start_profile_daemon "carol" "${CAROL_PROFILE_ID}"
  echo "devnet responders started"
}

run_stop() {
  if [[ -f "${PROFILE_FILE}" ]]; then
    load_profiles
    for profile_id in "${ALICE_PROFILE_ID:-}" "${BOB_PROFILE_ID:-}" "${CAROL_PROFILE_ID:-}"; do
      if [[ -n "${profile_id}" ]]; then
        managed_shell_cmd daemon stop --profile "${profile_id}" >/dev/null 2>&1 || true
      fi
    done
  fi

  if [[ -f "${PID_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${PID_FILE}"
    if [[ "${RELAY_OWNED:-0}" == "1" ]] && [[ -n "${RELAY_PID:-}" ]] && kill -0 "${RELAY_PID}" 2>/dev/null; then
      kill "${RELAY_PID}" || true
      wait "${RELAY_PID}" 2>/dev/null || true
      echo "stopped relay (${RELAY_PID})"
    fi
    rm -f "${PID_FILE}"
  fi
}

print_daemon_status() {
  local label="$1"
  local profile_id="$2"
  echo "== ${label} (${profile_id}) =="
  managed_shell_cmd daemon status --profile "${profile_id}" || true
}

run_status() {
  if [[ -f "${PID_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${PID_FILE}"
    if [[ -n "${RELAY_PID:-}" ]] && kill -0 "${RELAY_PID}" 2>/dev/null; then
      echo "relay: running (${RELAY_PID})"
    else
      echo "relay: stopped"
    fi
  else
    echo "relay: stopped"
  fi

  if [[ -f "${PROFILE_FILE}" ]]; then
    load_profiles
    print_daemon_status "alice" "${ALICE_PROFILE_ID}"
    print_daemon_status "bob" "${BOB_PROFILE_ID}"
    print_daemon_status "carol" "${CAROL_PROFILE_ID}"
  else
    echo "profiles: not generated"
  fi
}

run_smoke() {
  need_cmd cargo
  run_gen
  trap 'run_stop >/dev/null 2>&1 || true' EXIT INT TERM
  run_start

  managed_shell_cmd profile doctor "${ALICE_PROFILE_ID}" >/dev/null
  managed_shell_cmd daemon status --profile "${ALICE_PROFILE_ID}" >/dev/null
  managed_shell_cmd runtime status --profile "${ALICE_PROFILE_ID}" >/dev/null
  managed_shell_cmd runtime diagnostics --profile "${ALICE_PROFILE_ID}" >/dev/null
  managed_shell_cmd check sign --profile "${ALICE_PROFILE_ID}" >/dev/null
  managed_shell_cmd check ecdh --profile "${ALICE_PROFILE_ID}" >/dev/null
  local peer_json peer
  peer_json="$(managed_shell_cmd peer list --profile "${ALICE_PROFILE_ID}")"
  local first_peer=""
  while IFS= read -r peer; do
    [[ -n "${peer}" ]] || continue
    [[ -n "${first_peer}" ]] || first_peer="${peer}"
    managed_shell_cmd peer ping --profile "${ALICE_PROFILE_ID}" "${peer}" >/dev/null
    break
  done < <(printf '%s\n' "${peer_json}" | parse_json_pubkeys)
  if [[ -n "${first_peer}" ]]; then
    managed_shell_cmd peer onboard --profile "${ALICE_PROFILE_ID}" "${first_peer}" >/dev/null
    managed_shell_cmd policy set-peer-override \
      --profile "${ALICE_PROFILE_ID}" \
      "${first_peer}" \
      --direction request \
      --method sign \
      --value deny >/dev/null
    managed_shell_cmd policy clear-peer --profile "${ALICE_PROFILE_ID}" "${first_peer}" >/dev/null
  fi
  managed_shell_cmd runtime sign --profile "${ALICE_PROFILE_ID}" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null

  local onboard_path="${WORK_DIR}/smoke.bfonboard"
  IGLOO_SHELL_PACKAGE_PASSWORD="smoke-password" \
    managed_shell_cmd export "${ALICE_PROFILE_ID}" \
      --format bfonboard \
      --out "${onboard_path}" \
      --recipient-share "${MATERIAL_DIR}/share-bob.json" \
      --package-password-env IGLOO_SHELL_PACKAGE_PASSWORD >/dev/null
  if [[ ! -s "${onboard_path}" ]]; then
    echo "error: failed to export canonical bfonboard package" >&2
    exit 1
  fi

  echo "smoke complete"
}

cmd="${1:-}"
case "${cmd}" in
  gen) run_gen ;;
  start) run_start ;;
  start-responders) run_start_responders ;;
  stop) run_stop ;;
  status) run_status ;;
  smoke) run_smoke ;;
  *) usage; exit 1 ;;
esac
