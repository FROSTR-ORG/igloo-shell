use super::*;

#[cfg(unix)]
use bifrost_profile::fs_guard::{ensure_dir_restricted, write_restricted_bytes_atomic};

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

pub(crate) fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        // C.1/C.2: profile-bearing JSON manifests live in a directory tree
        // that we restrict to user-only. On Unix, route through the central
        // fs_guard helper so the dir lands at 0o700 and the file write is
        // atomic + 0o600 even under a relaxed inherited umask.
        #[cfg(unix)]
        ensure_dir_restricted(parent, 0o700)
            .with_context(|| format!("create {}", parent.display()))?;
        #[cfg(not(unix))]
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(value).context("serialize json")?;
    #[cfg(unix)]
    {
        write_restricted_bytes_atomic(path, raw.as_bytes(), 0o600)
            .with_context(|| format!("write {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        fs::write(path, raw).with_context(|| format!("write {}", path.display()))
    }
}
