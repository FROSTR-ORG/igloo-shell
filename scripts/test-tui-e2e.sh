#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHELL_MANIFEST="${ROOT_DIR}/Cargo.toml"
BIFROST_MANIFEST="${ROOT_DIR}/../bifrost-rs/Cargo.toml"
WORK_DIR="${WORK_DIR:-}"
TEMP_WORK_DIR=0
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
TEST_PASSED=0
TMUX_SESSION=""
if [[ -z "${WORK_DIR}" ]]; then
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/igloo-shell-tui-e2e.XXXXXX")"
  TEMP_WORK_DIR=1
fi
XDG_CONFIG_HOME="${WORK_DIR}/config"
XDG_DATA_HOME="${WORK_DIR}/data"
XDG_STATE_HOME="${WORK_DIR}/state"
MATERIAL_DIR="${WORK_DIR}/material"
LOG_DIR="${WORK_DIR}/logs"
RELAY_HOST="127.0.0.1"
RELAY_PORT="${RELAY_PORT:-8294}"
RELAY_URL="ws://${RELAY_HOST}:${RELAY_PORT}"
VAULT_PASSPHRASE="tui-e2e-passphrase"
ALICE_PROFILE_ID=""
BOB_PROFILE_ID=""
CAROL_PROFILE_ID=""

mkdir -p "${LOG_DIR}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

cleanup() {
  if [[ -n "${TMUX_SESSION:-}" ]] && tmux has-session -t "${TMUX_SESSION}" 2>/dev/null; then
    tmux kill-session -t "${TMUX_SESSION}" || true
  fi
  for profile_id in "${ALICE_PROFILE_ID:-}" "${BOB_PROFILE_ID:-}" "${CAROL_PROFILE_ID:-}"; do
    [[ -n "${profile_id}" ]] || continue
    env \
      XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
      XDG_DATA_HOME="${XDG_DATA_HOME}" \
      XDG_STATE_HOME="${XDG_STATE_HOME}" \
      IGLOO_SHELL_VAULT_PASSPHRASE="${VAULT_PASSPHRASE}" \
      cargo run --manifest-path "${SHELL_MANIFEST}" -p igloo-shell-cli --offline -- daemon stop --profile "${profile_id}" >/dev/null 2>&1 || true
  done
  if [[ -n "${RELAY_PID:-}" ]] && kill -0 "${RELAY_PID}" 2>/dev/null; then
    kill "${RELAY_PID}" || true
    wait "${RELAY_PID}" 2>/dev/null || true
  fi
  if [[ "${TEMP_WORK_DIR}" == "1" ]]; then
    if [[ "${TEST_PASSED}" == "1" && "${KEEP_WORK_DIR}" != "1" ]]; then
      rm -rf "${WORK_DIR}"
    else
      echo "tui e2e work dir: ${WORK_DIR}" >&2
    fi
  fi
}
trap cleanup EXIT INT TERM

need_cmd cargo
need_cmd tmux

shell_cmd() {
  env \
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
    XDG_DATA_HOME="${XDG_DATA_HOME}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    IGLOO_SHELL_VAULT_PASSPHRASE="${VAULT_PASSPHRASE}" \
    cargo run --manifest-path "${SHELL_MANIFEST}" -p igloo-shell-cli --offline -- "$@"
}

parse_json_field() {
  local field="$1"
  sed -n "s/^[[:space:]]*\"${field}\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

capture_step() {
  local session="$1"
  local name="$2"
  local out="${LOG_DIR}/${name}.txt"
  tmux capture-pane -pt "${session}" >"${out}"
  printf '%s\n' "${out}"
}

assert_capture_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! grep -Eq -- "${pattern}" "${file}"; then
    echo "${message}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

assert_capture_not_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if grep -Eq -- "${pattern}" "${file}"; then
    echo "${message}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

wait_for_runtime() {
  local profile_id="$1"
  local attempts="${2:-20}"
  local try
  for ((try = 1; try <= attempts; try++)); do
    if shell_cmd runtime status --profile "${profile_id}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_runtime_stop() {
  local profile_id="$1"
  local attempts="${2:-20}"
  local try
  for ((try = 1; try <= attempts; try++)); do
    if ! shell_cmd runtime status --profile "${profile_id}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_peer_list() {
  local profile_id="$1"
  local expected="$2"
  local attempts="${3:-20}"
  local try output count
  for ((try = 1; try <= attempts; try++)); do
    output="$(shell_cmd peer list --profile "${profile_id}" 2>/dev/null || true)"
    count="$(printf '%s\n' "${output}" | sed -n 's/^[[:space:]]*"pubkey":[[:space:]]*".*"/x/p' | wc -l | tr -d ' ')"
    if [[ "${count}" -ge "${expected}" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_profile_daemon() {
  local profile_id="$1"
  shell_cmd daemon start --profile "${profile_id}" >/dev/null
  if ! wait_for_runtime "${profile_id}" 20; then
    echo "daemon did not become queryable for ${profile_id}" >&2
    exit 1
  fi
}

mkdir -p "${MATERIAL_DIR}" "${LOG_DIR}"

cargo build --manifest-path "${SHELL_MANIFEST}" -p igloo-shell-cli --offline >/dev/null

cargo run --manifest-path "${BIFROST_MANIFEST}" -p bifrost-devtools --offline -- relay --host "${RELAY_HOST}" --port "${RELAY_PORT}" \
  >"${LOG_DIR}/relay.log" 2>&1 &
RELAY_PID=$!
sleep 2

cargo run --manifest-path "${BIFROST_MANIFEST}" -p bifrost-devtools --offline -- keygen \
  --out-dir "${MATERIAL_DIR}" \
  --threshold 2 \
  --count 3 \
  --relay "${RELAY_URL}" >/dev/null

env \
  XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
  XDG_DATA_HOME="${XDG_DATA_HOME}" \
  XDG_STATE_HOME="${XDG_STATE_HOME}" \
  cargo run --manifest-path "${SHELL_MANIFEST}" -p igloo-shell-cli --offline -- relays set local "${RELAY_URL}" >/dev/null

ALICE_IMPORT_JSON="$(
  shell_cmd import \
    --group "${MATERIAL_DIR}/group.json" \
    --share "${MATERIAL_DIR}/share-alice.json" \
    --label "alice" \
    --relay-profile local \
    --vault-secret "${VAULT_PASSPHRASE}" \
    --json
)"
BOB_IMPORT_JSON="$(
  shell_cmd import \
    --group "${MATERIAL_DIR}/group.json" \
    --share "${MATERIAL_DIR}/share-bob.json" \
    --label "bob" \
    --relay-profile local \
    --vault-secret "${VAULT_PASSPHRASE}" \
    --json
)"
CAROL_IMPORT_JSON="$(
  shell_cmd import \
    --group "${MATERIAL_DIR}/group.json" \
    --share "${MATERIAL_DIR}/share-carol.json" \
    --label "carol" \
    --relay-profile local \
    --vault-secret "${VAULT_PASSPHRASE}" \
    --json
)"

ALICE_PROFILE_ID="$(printf '%s\n' "${ALICE_IMPORT_JSON}" | parse_json_field "id")"
BOB_PROFILE_ID="$(printf '%s\n' "${BOB_IMPORT_JSON}" | parse_json_field "id")"
CAROL_PROFILE_ID="$(printf '%s\n' "${CAROL_IMPORT_JSON}" | parse_json_field "id")"
if [[ -z "${ALICE_PROFILE_ID}" || -z "${BOB_PROFILE_ID}" || -z "${CAROL_PROFILE_ID}" ]]; then
  echo "failed to parse imported profile ids" >&2
  printf '%s\n%s\n%s\n' "${ALICE_IMPORT_JSON}" "${BOB_IMPORT_JSON}" "${CAROL_IMPORT_JSON}" >&2
  exit 1
fi

start_profile_daemon "${BOB_PROFILE_ID}"
start_profile_daemon "${CAROL_PROFILE_ID}"

TMUX_SESSION="igloo-shell-tui-e2e-$$"
tmux new-session -d -s "${TMUX_SESSION}" "cd '${ROOT_DIR}' && env XDG_CONFIG_HOME='${XDG_CONFIG_HOME}' XDG_DATA_HOME='${XDG_DATA_HOME}' XDG_STATE_HOME='${XDG_STATE_HOME}' cargo run --manifest-path '${SHELL_MANIFEST}' -p igloo-shell-cli --offline -- profile load '${ALICE_PROFILE_ID}'"
sleep 1
STEP_FILE="$(capture_step "${TMUX_SESSION}" "unlock-modal")"
assert_capture_contains "${STEP_FILE}" "Vault secret" "load did not prompt for the vault secret"

tmux send-keys -t "${TMUX_SESSION}" "${VAULT_PASSPHRASE}"
tmux send-keys -t "${TMUX_SESSION}" Enter
sleep 2
STEP_FILE="$(capture_step "${TMUX_SESSION}" "dashboard-initial")"
assert_capture_contains "${STEP_FILE}" "Dashboard" "tui did not render Dashboard after unlock"
if ! wait_for_runtime "${ALICE_PROFILE_ID}" 20; then
  echo "tui did not auto-start alice daemon" >&2
  exit 1
fi
if ! wait_for_peer_list "${ALICE_PROFILE_ID}" 2 20; then
  echo "alice peer list never populated after tui auto-start" >&2
  exit 1
fi

tmux send-keys -t "${TMUX_SESSION}" Right
sleep 1
STEP_FILE="$(capture_step "${TMUX_SESSION}" "permissions-tab")"
assert_capture_contains "${STEP_FILE}" "Permissions" "tui did not switch to Permissions tab"
assert_capture_contains "${STEP_FILE}" "default" "permissions table did not render"

tmux send-keys -t "${TMUX_SESSION}" Down
tmux send-keys -t "${TMUX_SESSION}" Enter
sleep 1
STEP_FILE="$(capture_step "${TMUX_SESSION}" "permissions-cycle")"
assert_capture_contains "${STEP_FILE}" "rq\\.ping set to allow" "tui did not update the selected per-method override from Permissions"

sleep 1
tmux send-keys -t "${TMUX_SESSION}" Up
tmux send-keys -t "${TMUX_SESSION}" Right
sleep 1
STEP_FILE="$(capture_step "${TMUX_SESSION}" "settings-tab")"
assert_capture_contains "${STEP_FILE}" "Settings" "tui did not switch to Settings tab"
assert_capture_contains "${STEP_FILE}" "Stop Daemon|Start Daemon" "settings actions did not render"

tmux send-keys -t "${TMUX_SESSION}" Escape
if ! wait_for_runtime_stop "${ALICE_PROFILE_ID}" 20; then
  echo "logout did not stop alice daemon" >&2
  exit 1
fi
sleep 1
if tmux has-session -t "${TMUX_SESSION}" 2>/dev/null; then
  echo "logout did not exit the load session" >&2
  STEP_FILE="$(capture_step "${TMUX_SESSION}" "logout-still-running")"
  cat "${STEP_FILE}" >&2
  exit 1
fi

TEST_PASSED=1
echo "tui e2e passed"
