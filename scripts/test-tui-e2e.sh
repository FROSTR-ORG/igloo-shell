#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${ROOT_DIR}/dev/data/tui-e2e"
XDG_CONFIG_HOME="${WORK_DIR}/config"
XDG_DATA_HOME="${WORK_DIR}/data"
XDG_STATE_HOME="${WORK_DIR}/state"
MATERIAL_DIR="${WORK_DIR}/material"
LOG_DIR="${WORK_DIR}/logs"
OUT_FILE="${LOG_DIR}/tui-output.txt"
RELAY_HOST="127.0.0.1"
RELAY_PORT="${RELAY_PORT:-8294}"
RELAY_URL="ws://${RELAY_HOST}:${RELAY_PORT}"
VAULT_PASSPHRASE="tui-e2e-passphrase"

mkdir -p "${LOG_DIR}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

cleanup() {
  if [[ -n "${DAEMON_PROFILE_ID:-}" ]]; then
    env \
      XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
      XDG_DATA_HOME="${XDG_DATA_HOME}" \
      XDG_STATE_HOME="${XDG_STATE_HOME}" \
      IGLOO_SHELL_VAULT_PASSPHRASE="${VAULT_PASSPHRASE}" \
      cargo run -p igloo-shell-cli --offline -- daemon stop --profile "${DAEMON_PROFILE_ID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${RELAY_PID:-}" ]] && kill -0 "${RELAY_PID}" 2>/dev/null; then
    kill "${RELAY_PID}" || true
    wait "${RELAY_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

need_cmd cargo
need_cmd tmux

rm -rf "${WORK_DIR}"
mkdir -p "${MATERIAL_DIR}" "${LOG_DIR}"

cargo build -p igloo-shell-cli -p igloo-shell-tui --offline >/dev/null

cargo run -p igloo-shell-cli --offline -- dev relay --host "${RELAY_HOST}" --port "${RELAY_PORT}" \
  >"${LOG_DIR}/relay.log" 2>&1 &
RELAY_PID=$!
sleep 2

cargo run -p igloo-shell-cli --offline -- dev keygen \
  --out-dir "${MATERIAL_DIR}" \
  --threshold 2 \
  --count 3 \
  --relay "${RELAY_URL}" >/dev/null

env \
  XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
  XDG_DATA_HOME="${XDG_DATA_HOME}" \
  XDG_STATE_HOME="${XDG_STATE_HOME}" \
  cargo run -p igloo-shell-cli --offline -- relays set local "${RELAY_URL}" >/dev/null

IMPORT_JSON="$(
  env \
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
    XDG_DATA_HOME="${XDG_DATA_HOME}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    IGLOO_SHELL_VAULT_PASSPHRASE="${VAULT_PASSPHRASE}" \
    cargo run -p igloo-shell-cli --offline -- profile import \
      --group "${MATERIAL_DIR}/group.json" \
      --share "${MATERIAL_DIR}/share-alice.json" \
      --label "alice" \
      --relay-profile local
)"

DAEMON_PROFILE_ID="$(printf '%s\n' "${IMPORT_JSON}" | sed -n 's/^[[:space:]]*"id":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
if [[ -z "${DAEMON_PROFILE_ID}" ]]; then
  echo "failed to parse imported profile id" >&2
  printf '%s\n' "${IMPORT_JSON}" >&2
  exit 1
fi

env \
  XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
  XDG_DATA_HOME="${XDG_DATA_HOME}" \
  XDG_STATE_HOME="${XDG_STATE_HOME}" \
  IGLOO_SHELL_VAULT_PASSPHRASE="${VAULT_PASSPHRASE}" \
  cargo run -p igloo-shell-cli --offline -- daemon start --profile "${DAEMON_PROFILE_ID}" >/dev/null

TMUX_SESSION="igloo-shell-tui-e2e-$$"
tmux new-session -d -s "${TMUX_SESSION}" "cd '${ROOT_DIR}' && env XDG_CONFIG_HOME='${XDG_CONFIG_HOME}' XDG_DATA_HOME='${XDG_DATA_HOME}' XDG_STATE_HOME='${XDG_STATE_HOME}' IGLOO_SHELL_VAULT_PASSPHRASE='${VAULT_PASSPHRASE}' cargo run -p igloo-shell-cli --offline -- tui --profile '${DAEMON_PROFILE_ID}'"
sleep 2
tmux capture-pane -pt "${TMUX_SESSION}" >"${OUT_FILE}"

if ! grep -q "Overview" "${OUT_FILE}"; then
  echo "tui did not render Overview screen" >&2
  cat "${OUT_FILE}" >&2
  tmux kill-session -t "${TMUX_SESSION}" || true
  exit 1
fi

tmux send-keys -t "${TMUX_SESSION}" Tab
sleep 1
tmux capture-pane -pt "${TMUX_SESSION}" >>"${OUT_FILE}"
if ! grep -q "Peers" "${OUT_FILE}"; then
  echo "tui did not switch to Peers screen" >&2
  cat "${OUT_FILE}" >&2
  tmux kill-session -t "${TMUX_SESSION}" || true
  exit 1
fi

tmux send-keys -t "${TMUX_SESSION}" Tab
sleep 1
tmux capture-pane -pt "${TMUX_SESSION}" >>"${OUT_FILE}"
if ! grep -q "Invites" "${OUT_FILE}"; then
  echo "tui did not switch to Invites screen" >&2
  cat "${OUT_FILE}" >&2
  tmux kill-session -t "${TMUX_SESSION}" || true
  exit 1
fi

tmux send-keys -t "${TMUX_SESSION}" c
sleep 1
tmux capture-pane -pt "${TMUX_SESSION}" >>"${OUT_FILE}"
if ! grep -Eq -- '[0-9a-f]{6}\.\.[0-9a-f]{4}[[:space:]]+1[[:space:]]+[0-9]{10}[[:space:]]+[0-9]{10}[[:space:]]+no[[:space:]]+[0-9a-f]{6}\.\.[0-9a-f]{4}' "${OUT_FILE}"; then
  echo "tui did not create invite" >&2
  cat "${OUT_FILE}" >&2
  tmux kill-session -t "${TMUX_SESSION}" || true
  exit 1
fi

tmux send-keys -t "${TMUX_SESSION}" q
sleep 1
tmux kill-session -t "${TMUX_SESSION}" >/dev/null 2>&1 || true

echo "tui e2e passed"
