#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${ROOT_DIR}/dev/data/devnet"
XDG_CONFIG_HOME="${WORK_DIR}/config"
XDG_DATA_HOME="${WORK_DIR}/data"
XDG_STATE_HOME="${WORK_DIR}/state"
PROFILE_FILE="${WORK_DIR}/profiles.env"
VAULT_PASSPHRASE="${IGLOO_SHELL_VAULT_PASSPHRASE:-devnet-passphrase}"
MESSAGE_HEX32="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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

load_profiles() {
  if [[ ! -f "${PROFILE_FILE}" ]]; then
    echo "missing profile file: ${PROFILE_FILE}" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${PROFILE_FILE}"
}

cleanup() {
  bash "${ROOT_DIR}/scripts/devnet.sh" stop >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cd "${ROOT_DIR}"
bash "${ROOT_DIR}/scripts/devnet.sh" gen
bash "${ROOT_DIR}/scripts/devnet.sh" start
load_profiles

managed_shell_cmd profile doctor "${ALICE_PROFILE_ID}" >/dev/null
managed_shell_cmd daemon status --profile "${ALICE_PROFILE_ID}" >/dev/null
managed_shell_cmd runtime status --profile "${ALICE_PROFILE_ID}" >/dev/null
managed_shell_cmd runtime diagnostics --profile "${ALICE_PROFILE_ID}" >/dev/null
managed_shell_cmd check sign --profile "${ALICE_PROFILE_ID}" >/dev/null
managed_shell_cmd check ecdh --profile "${ALICE_PROFILE_ID}" >/dev/null
PEER_JSON="$(managed_shell_cmd peer list --profile "${ALICE_PROFILE_ID}")"
FIRST_PEER=""
while IFS= read -r PEER_PUBKEY; do
  [[ -n "${PEER_PUBKEY}" ]] || continue
  [[ -n "${FIRST_PEER}" ]] || FIRST_PEER="${PEER_PUBKEY}"
  managed_shell_cmd peer ping --profile "${ALICE_PROFILE_ID}" "${PEER_PUBKEY}" >/dev/null
  break
done < <(printf '%s\n' "${PEER_JSON}" | parse_json_pubkeys)
if [[ -n "${FIRST_PEER}" ]]; then
  managed_shell_cmd peer onboard --profile "${ALICE_PROFILE_ID}" "${FIRST_PEER}" >/dev/null
fi

SIGN_JSON="$(managed_shell_cmd runtime sign --profile "${ALICE_PROFILE_ID}" "${MESSAGE_HEX32}")"
SIGNATURE="$(printf '%s\n' "${SIGN_JSON}" | sed -n 's/^[[:space:]]*"\([0-9a-f]\{128\}\)".*/\1/p' | head -n 1)"
if [[ "${#SIGNATURE}" -ne 128 ]]; then
  echo "invalid signature output" >&2
  printf '%s\n' "${SIGN_JSON}" >&2
  exit 1
fi

ONBOARD_PATH="${WORK_DIR}/node-e2e.bfonboard"
IGLOO_SHELL_PACKAGE_PASSWORD="node-e2e-password" \
  managed_shell_cmd export "${ALICE_PROFILE_ID}" \
    --format bfonboard \
    --out "${ONBOARD_PATH}" \
    --recipient-share "${WORK_DIR}/material/share-bob.json" \
    --package-password-env IGLOO_SHELL_PACKAGE_PASSWORD >/dev/null
if [[ ! -s "${ONBOARD_PATH}" ]]; then
  echo "failed to export canonical bfonboard package" >&2
  exit 1
fi

RAW_PATH="${WORK_DIR}/node-e2e.raw.json"
managed_shell_cmd export "${ALICE_PROFILE_ID}" \
  --format raw \
  --out "${RAW_PATH}" >/dev/null
if [[ ! -s "${RAW_PATH}" ]]; then
  echo "failed to export raw profile package" >&2
  exit 1
fi

managed_shell_cmd profile backup "${ALICE_PROFILE_ID}" \
  --vault-passphrase-env IGLOO_SHELL_VAULT_PASSPHRASE >/dev/null
RECOVERY_PATH="${WORK_DIR}/node-e2e.bfshare"
IGLOO_SHELL_PACKAGE_PASSWORD="node-e2e-share-password" \
  managed_shell_cmd export "${ALICE_PROFILE_ID}" \
    --format bfshare \
    --out "${RECOVERY_PATH}" \
    --package-password-env IGLOO_SHELL_PACKAGE_PASSWORD >/dev/null
if [[ ! -s "${RECOVERY_PATH}" ]]; then
  echo "failed to export bfshare package" >&2
  exit 1
fi

RECOVER_JSON="$(
  managed_shell_cmd recover "${RECOVERY_PATH}" \
    --label "alice-recovered" \
    --package-secret "node-e2e-share-password" \
    --vault-secret "${VAULT_PASSPHRASE}" \
    --json
)"
RECOVERED_PROFILE_ID="$(printf '%s\n' "${RECOVER_JSON}" | parse_json_field "id")"
if [[ -z "${RECOVERED_PROFILE_ID}" ]]; then
  echo "failed to recover profile from bfshare" >&2
  printf '%s\n' "${RECOVER_JSON}" >&2
  exit 1
fi

ROTATE_PATH="${WORK_DIR}/node-rotate.bfonboard"
IGLOO_SHELL_PACKAGE_PASSWORD="node-rotate-password" \
  managed_shell_cmd export "${BOB_PROFILE_ID}" \
    --format bfonboard \
    --out "${ROTATE_PATH}" \
    --recipient-share "${WORK_DIR}/material/share-dave.json" \
    --package-password-env IGLOO_SHELL_PACKAGE_PASSWORD >/dev/null
if [[ ! -s "${ROTATE_PATH}" ]]; then
  echo "failed to export rotation bfonboard package" >&2
  exit 1
fi

ROTATE_JSON="$(
  managed_shell_cmd rotate-key "${ROTATE_PATH}" \
    --profile "${ALICE_PROFILE_ID}" \
    --onboard-secret "node-rotate-password" \
    --vault-secret "${VAULT_PASSPHRASE}" \
    --daemon \
    --json
)"
REPLACED_PROFILE_ID="$(printf '%s\n' "${ROTATE_JSON}" | parse_json_field "profile_id")"
if [[ -z "${REPLACED_PROFILE_ID}" || "${REPLACED_PROFILE_ID}" == "${ALICE_PROFILE_ID}" ]]; then
  echo "failed to rotate profile in place" >&2
  printf '%s\n' "${ROTATE_JSON}" >&2
  exit 1
fi
managed_shell_cmd daemon status --profile "${REPLACED_PROFILE_ID}" >/dev/null
managed_shell_cmd runtime status --profile "${REPLACED_PROFILE_ID}" >/dev/null

echo "node e2e passed"
