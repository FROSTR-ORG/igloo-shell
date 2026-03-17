#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION_NAME="igloo-demo"
DEVNET_SCRIPT="${ROOT_DIR}/scripts/devnet.sh"
WORK_DIR="${ROOT_DIR}/dev/data/devnet"
XDG_CONFIG_HOME="${WORK_DIR}/config"
XDG_DATA_HOME="${WORK_DIR}/data"
XDG_STATE_HOME="${WORK_DIR}/state"
LOG_DIR="${WORK_DIR}/logs"
PROFILE_FILE="${WORK_DIR}/profiles.env"
VAULT_PASSPHRASE="${IGLOO_SHELL_VAULT_PASSPHRASE:-devnet-passphrase}"

usage() {
  cat <<USAGE
Usage: scripts/devnet-tmux.sh <command> [--no-attach]

Commands:
  start [--no-attach]   Generate/start managed devnet and open tmux layout
  stop                  Stop tmux session and managed devnet
  status                Show tmux + devnet status
USAGE
}

ensure_tmux() {
  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux is required" >&2
    exit 1
  fi
}

load_profiles() {
  if [[ ! -f "${PROFILE_FILE}" ]]; then
    echo "error: managed profiles not found; run scripts/devnet.sh gen first" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${PROFILE_FILE}"
}

managed_prefix() {
  printf "env XDG_CONFIG_HOME='%s' XDG_DATA_HOME='%s' XDG_STATE_HOME='%s' IGLOO_SHELL_VAULT_PASSPHRASE='%s'" \
    "${XDG_CONFIG_HOME}" "${XDG_DATA_HOME}" "${XDG_STATE_HOME}" "${VAULT_PASSPHRASE}"
}

create_layout() {
  local no_attach="$1"
  local env_prefix
  env_prefix="$(managed_prefix)"

  tmux new-session -d -s "${SESSION_NAME}" -n demo \
    "cd '${ROOT_DIR}' && bash"
  tmux split-window -h -t "${SESSION_NAME}:demo.0"
  tmux split-window -v -t "${SESSION_NAME}:demo.0"
  tmux split-window -v -t "${SESSION_NAME}:demo.1"
  tmux select-layout -t "${SESSION_NAME}:demo" tiled

  tmux send-keys -t "${SESSION_NAME}:demo.0" \
    "cd '${ROOT_DIR}' && clear && echo 'Relay log (Ctrl+b d to detach)' && exec tail -n +1 -f '${LOG_DIR}/relay.log'" C-m
  tmux send-keys -t "${SESSION_NAME}:demo.1" \
    "cd '${ROOT_DIR}' && clear && exec ${env_prefix} cargo run -p igloo-shell-cli --offline -- profile load '${ALICE_PROFILE_ID}' --vault-secret '${VAULT_PASSPHRASE}'" C-m
  tmux send-keys -t "${SESSION_NAME}:demo.2" \
    "cd '${ROOT_DIR}' && clear && exec ${env_prefix} cargo run -p igloo-shell-cli --offline -- daemon logs --follow --profile '${BOB_PROFILE_ID}'" C-m
  tmux send-keys -t "${SESSION_NAME}:demo.3" \
    "cd '${ROOT_DIR}' && clear && exec ${env_prefix} cargo run -p igloo-shell-cli --offline -- daemon logs --follow --profile '${CAROL_PROFILE_ID}'" C-m

  tmux select-pane -t "${SESSION_NAME}:demo.1"

  if [[ "${no_attach}" == "1" ]]; then
    echo "tmux session created: ${SESSION_NAME}"
    echo "attach with: tmux attach -t ${SESSION_NAME}"
  else
    tmux attach-session -t "${SESSION_NAME}" || true
  fi
}

start_cmd() {
  local no_attach="0"
  if [[ "${1:-}" == "--no-attach" ]]; then
    no_attach="1"
  fi

  ensure_tmux

  if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
    tmux kill-session -t "${SESSION_NAME}" || true
  fi

  "${DEVNET_SCRIPT}" gen
  "${DEVNET_SCRIPT}" start
  load_profiles

  cleanup() {
    "${DEVNET_SCRIPT}" stop || true
    if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
      tmux kill-session -t "${SESSION_NAME}" || true
    fi
  }

  if [[ "${no_attach}" == "1" ]]; then
    create_layout "1"
    return
  fi

  trap cleanup EXIT INT TERM
  create_layout "0"
}

stop_cmd() {
  ensure_tmux
  if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
    tmux kill-session -t "${SESSION_NAME}" || true
  fi
  "${DEVNET_SCRIPT}" stop || true
}

status_cmd() {
  ensure_tmux
  if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
    echo "tmux: running (${SESSION_NAME})"
  else
    echo "tmux: stopped"
  fi
  "${DEVNET_SCRIPT}" status
}

cmd="${1:-}"
case "${cmd}" in
  start)
    shift
    start_cmd "${1:-}"
    ;;
  stop)
    stop_cmd
    ;;
  status)
    status_cmd
    ;;
  *)
    usage
    exit 1
    ;;
esac
