use std::fs;

use anyhow::{Context, Result, anyhow};
use bifrost_core::secret::Passphrase;
use bifrost_profile::{
    EncryptedProfileStore, FilesystemEncryptedProfileStore, FilesystemProfileManifestStore,
    ProfileManifestStore,
};

use super::{ProfileManifest, ShellPaths, now_unix_secs};

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
    passphrase: Option<&Passphrase>,
) -> Result<bifrost_profile::EncryptedProfileRecord> {
    // C.5: env-var fallback removed; callers thread a `Passphrase` explicitly.
    let passphrase = passphrase.ok_or_else(|| anyhow!("passphrase not provided"))?;
    encrypted_profile_store(paths).store_encrypted_profile(
        kind,
        source,
        payload,
        passphrase.expose_secret(),
        now_unix_secs(),
    )
}

pub(crate) fn decrypt_encrypted_profile(
    paths: &ShellPaths,
    record: &bifrost_profile::EncryptedProfileRecord,
    passphrase: Option<&Passphrase>,
) -> Result<String> {
    let passphrase = passphrase.ok_or_else(|| anyhow!("passphrase not provided"))?;
    encrypted_profile_store(paths).decrypt_encrypted_profile(record, passphrase.expose_secret())
}

pub(crate) fn load_share_payload(paths: &ShellPaths, profile: &ProfileManifest) -> Result<String> {
    load_share_payload_with_passphrase(paths, profile, None)
}

pub(crate) fn load_share_payload_with_passphrase(
    paths: &ShellPaths,
    profile: &ProfileManifest,
    passphrase: Option<&Passphrase>,
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
    passphrase: Option<&Passphrase>,
) -> Result<()> {
    let _ = load_share_payload_with_passphrase(paths, profile, passphrase)?;
    Ok(())
}

pub fn validate_profile_unlock_with_passphrase(
    paths: &ShellPaths,
    profile_id: &str,
    passphrase: Option<&Passphrase>,
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
