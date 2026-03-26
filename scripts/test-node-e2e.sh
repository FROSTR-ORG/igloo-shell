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
managed_shell_cmd check onboard --profile "${ALICE_PROFILE_ID}" >/dev/null
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
RECOVERED_PROFILE_ID="$(
  printf '%s\n' "${RECOVER_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["import"]["profile"]["id"])'
)"
if [[ -z "${RECOVERED_PROFILE_ID}" ]]; then
  echo "failed to recover profile from bfshare" >&2
  printf '%s\n' "${RECOVER_JSON}" >&2
  exit 1
fi

managed_shell_cmd profile backup "${BOB_PROFILE_ID}" \
  --vault-passphrase-env IGLOO_SHELL_VAULT_PASSPHRASE >/dev/null
ROTATESET_SOURCE_A="${WORK_DIR}/rotate-source-alice.bfshare"
ROTATESET_SOURCE_B="${WORK_DIR}/rotate-source-bob.bfshare"
IGLOO_SHELL_PACKAGE_PASSWORD="rotate-source-alice-password" \
  managed_shell_cmd export "${ALICE_PROFILE_ID}" \
    --format bfshare \
    --out "${ROTATESET_SOURCE_A}" \
    --package-password-env IGLOO_SHELL_PACKAGE_PASSWORD >/dev/null
IGLOO_SHELL_PACKAGE_PASSWORD="rotate-source-bob-password" \
  managed_shell_cmd export "${BOB_PROFILE_ID}" \
    --format bfshare \
    --out "${ROTATESET_SOURCE_B}" \
    --package-password-env IGLOO_SHELL_PACKAGE_PASSWORD >/dev/null
if [[ ! -s "${ROTATESET_SOURCE_A}" || ! -s "${ROTATESET_SOURCE_B}" ]]; then
  echo "failed to export rotate-keyset source packages" >&2
  exit 1
fi

ROTATESET_WORKSPACE="${WORK_DIR}/rotate-keyset"
managed_shell_cmd rotate-keyset init \
  --profile "${ALICE_PROFILE_ID}" \
  --threshold 2 \
  --count 4 \
  --workspace "${ROTATESET_WORKSPACE}" \
  --source-bfshare "${ROTATESET_SOURCE_A}" \
  --source-bfshare "${ROTATESET_SOURCE_B}" \
  --vault-secret "${VAULT_PASSPHRASE}" >/dev/null

ROTATESET_MANIFEST="${ROTATESET_WORKSPACE}/rotation.json"
perl -0pi -e 's/"package_secret_env": null/"package_secret_env": "ROTATE_SOURCE_SECRET_A"/; s/"package_secret_env": null/"package_secret_env": "ROTATE_SOURCE_SECRET_B"/;' "${ROTATESET_MANIFEST}"
managed_shell_cmd rotate-keyset show --workspace "${ROTATESET_WORKSPACE}" >/dev/null

ROTATESET_JSON="$(
  env \
    ROTATE_SOURCE_SECRET_A="rotate-source-alice-password" \
    ROTATE_SOURCE_SECRET_B="rotate-source-bob-password" \
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
    XDG_DATA_HOME="${XDG_DATA_HOME}" \
    XDG_STATE_HOME="${XDG_STATE_HOME}" \
    IGLOO_SHELL_VAULT_PASSPHRASE="${VAULT_PASSPHRASE}" \
    cargo run -p igloo-shell-cli --offline -- rotate-keyset generate \
      --workspace "${ROTATESET_WORKSPACE}" \
      --vault-secret "${VAULT_PASSPHRASE}" \
      --distribution-secret "rotate-keyset-password" \
      --daemon \
      --json
)"
ROTATESET_REPLACED_ID="$(
  printf '%s\n' "${ROTATESET_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["rotation_generate"]["replaced_profile_id"])'
)"
ROTATESET_PROFILE_ID="$(
  printf '%s\n' "${ROTATESET_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["rotation_generate"]["profile"]["id"])'
)"
if [[ -z "${ROTATESET_PROFILE_ID}" || "${ROTATESET_PROFILE_ID}" == "${ROTATESET_REPLACED_ID}" ]]; then
  echo "failed to generate rotated keyset" >&2
  printf '%s\n' "${ROTATESET_JSON}" >&2
  exit 1
fi
managed_shell_cmd daemon status --profile "${ROTATESET_PROFILE_ID}" >/dev/null
managed_shell_cmd runtime status --profile "${ROTATESET_PROFILE_ID}" >/dev/null

ROTATESET_REMOTE_PATH="$(find "${ROTATESET_WORKSPACE}/packages" -name '*.bfonboard.txt' | sort | tail -n 1)"
if [[ -z "${ROTATESET_REMOTE_PATH}" || ! -s "${ROTATESET_REMOTE_PATH}" ]]; then
  echo "failed to emit rotate-keyset bfonboard packages" >&2
  exit 1
fi
ROTATESET_ONBOARD_PATH="${ROTATESET_WORKSPACE}/packages/member-3.bfonboard.txt"
ROTATESET_ROTATE_PATH="${ROTATESET_WORKSPACE}/packages/member-2.bfonboard.txt"
if [[ ! -s "${ROTATESET_ONBOARD_PATH}" || ! -s "${ROTATESET_ROTATE_PATH}" ]]; then
  echo "failed to create expected rotate-keyset package outputs" >&2
  exit 1
fi

ROTATESET_ONBOARDED_JSON="$(
  managed_shell_cmd onboard "${ROTATESET_ONBOARD_PATH}" \
    --label "rotate-keyset-onboarded" \
    --onboard-secret "rotate-keyset-password" \
    --vault-secret "${VAULT_PASSPHRASE}" \
    --json
)"
ROTATESET_ONBOARDED_ID="$(
  printf '%s\n' "${ROTATESET_ONBOARDED_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["import"]["profile"]["id"])'
)"
if [[ -z "${ROTATESET_ONBOARDED_ID}" ]]; then
  echo "failed to onboard emitted rotate-keyset package" >&2
  printf '%s\n' "${ROTATESET_ONBOARDED_JSON}" >&2
  exit 1
fi
managed_shell_cmd daemon start --profile "${ROTATESET_ONBOARDED_ID}" >/dev/null
managed_shell_cmd runtime status --profile "${ROTATESET_ONBOARDED_ID}" >/dev/null

ROTATE_JSON="$(
  managed_shell_cmd rotate-key "${ROTATESET_ROTATE_PATH}" \
    --profile "${BOB_PROFILE_ID}" \
    --onboard-secret "rotate-keyset-password" \
    --vault-secret "${VAULT_PASSPHRASE}" \
    --daemon \
    --json
)"
REPLACED_PROFILE_ID="$(printf '%s\n' "${ROTATE_JSON}" | parse_json_field "profile_id")"
if [[ -z "${REPLACED_PROFILE_ID}" || "${REPLACED_PROFILE_ID}" == "${BOB_PROFILE_ID}" ]]; then
  echo "failed to rotate existing profile from emitted rotate-keyset package" >&2
  printf '%s\n' "${ROTATE_JSON}" >&2
  exit 1
fi
managed_shell_cmd daemon status --profile "${REPLACED_PROFILE_ID}" >/dev/null
managed_shell_cmd runtime status --profile "${REPLACED_PROFILE_ID}" >/dev/null

echo "node e2e passed"
