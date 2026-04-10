use std::fs;

use anyhow::{Context, Result};
use bifrost_profile::{
    EncryptedProfileStore, FilesystemEncryptedProfileStore, FilesystemProfileManifestStore,
    ProfileManifestStore,
};

use super::{PROFILE_PASSPHRASE_ENV, ProfileManifest, ShellPaths, now_unix_secs};

fn encrypted_profile_store(paths: &ShellPaths) -> FilesystemEncryptedProfileStore {
    FilesystemEncryptedProfileStore::new(
        &paths.encrypted_profiles_dir,
        &paths.encrypted_profiles_dir,
    )
}

fn profile_store(paths: &ShellPaths) -> FilesystemProfileManifestStore {
    FilesystemProfileManifestStore::new(&paths.profiles_dir)
}

pub fn read_encrypted_profile(
    paths: &ShellPaths,
    encrypted_profile_id: &str,
) -> Result<bifrost_profile::EncryptedProfileRecord> {
    encrypted_profile_store(paths).read_encrypted_profile(encrypted_profile_id)
}

pub fn write_encrypted_profile(
    paths: &ShellPaths,
    record: &bifrost_profile::EncryptedProfileRecord,
) -> Result<()> {
    encrypted_profile_store(paths).write_encrypted_profile(record)
}

pub(crate) fn store_encrypted_profile(
    paths: &ShellPaths,
    kind: &str,
    source: &str,
    payload: &str,
    passphrase: Option<String>,
) -> Result<bifrost_profile::EncryptedProfileRecord> {
    let passphrase = resolve_secret(passphrase, PROFILE_PASSPHRASE_ENV, "passphrase")?;
    encrypted_profile_store(paths).store_encrypted_profile(
        kind,
        source,
        payload,
        &passphrase,
        now_unix_secs(),
    )
}

pub(crate) fn decrypt_encrypted_profile(
    paths: &ShellPaths,
    record: &bifrost_profile::EncryptedProfileRecord,
    passphrase: Option<String>,
) -> Result<String> {
    let passphrase = resolve_secret(passphrase, PROFILE_PASSPHRASE_ENV, "passphrase")?;
    encrypted_profile_store(paths).decrypt_encrypted_profile(record, &passphrase)
}

pub(crate) fn resolve_secret(value: Option<String>, env_name: &str, label: &str) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    std::env::var(env_name).with_context(|| format!("{label} not provided; set {env_name}"))
}

pub(crate) fn load_share_payload(paths: &ShellPaths, profile: &ProfileManifest) -> Result<String> {
    load_share_payload_with_passphrase(paths, profile, None)
}

pub(crate) fn load_share_payload_with_passphrase(
    paths: &ShellPaths,
    profile: &ProfileManifest,
    passphrase: Option<String>,
) -> Result<String> {
    if let Ok(record) = read_encrypted_profile(paths, &profile.encrypted_profile_ref) {
        return decrypt_encrypted_profile(paths, &record, passphrase);
    }
    fs::read_to_string(&profile.encrypted_profile_ref)
        .with_context(|| format!("read {}", profile.encrypted_profile_ref))
}

pub(crate) fn validate_profile_unlock(
    paths: &ShellPaths,
    profile: &ProfileManifest,
    passphrase: Option<String>,
) -> Result<()> {
    let _ = load_share_payload_with_passphrase(paths, profile, passphrase)?;
    Ok(())
}

pub fn validate_profile_unlock_with_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let profile = profile_store(paths).read_profile(profile_id)?;
    validate_profile_unlock(paths, &profile, passphrase)
}

pub(crate) fn remove_encrypted_profile(
    paths: &ShellPaths,
    encrypted_profile_id: &str,
) -> Result<()> {
    encrypted_profile_store(paths).remove_encrypted_profile(encrypted_profile_id)
}
