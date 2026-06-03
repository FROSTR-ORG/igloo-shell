use super::super::*;
use bifrost_core::secret::Passphrase;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    StatusOnly,
    StartAttached,
    StartBackground,
}

pub fn resolve_onboard_secret(value: Option<String>, file: Option<String>) -> Result<String> {
    resolve_secret_source_with(
        value,
        file,
        std::io::stdin().is_terminal(),
        "onboard-secret",
        "onboard requires onboarding secret input; use --onboard-secret / --onboard-secret-file, or run on a TTY",
        || super::prompts::prompt_onboarding_secret().map(|p| p.expose_secret().to_string()),
    )
}

pub fn resolve_profile_label(value: Option<String>) -> Result<String> {
    resolve_profile_label_with(
        value,
        std::io::stdin().is_terminal(),
        super::prompts::prompt_profile_label,
    )
}

pub fn resolve_profile_label_with<F>(
    value: Option<String>,
    stdin_is_terminal: bool,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        Some(_) => bail!("label cannot be empty"),
        None if stdin_is_terminal => prompt(),
        None => bail!("onboard requires --label when stdin is not a TTY"),
    }
}

/// Resolve a `Passphrase` from `--passphrase` / `--passphrase-file` / TTY
/// prompt / stdin pipe (when stdin is a pipe, not a TTY).
///
/// Bucket C C.3/C.5: returns `Passphrase` (zeroize-on-drop, redacted Debug)
/// directly so the secret never lives as a bare `String` across the call
/// site. Stdin-pipe mode lets scripted callers do
/// `echo "$PASSPHRASE" | igloo-shell ...` in place of the retired
/// passphrase env-var contract.
pub fn resolve_passphrase(value: Option<String>, file: Option<String>) -> Result<Passphrase> {
    resolve_passphrase_source_with(
        value,
        file,
        std::io::stdin().is_terminal(),
        "encrypted-profile-secret",
        "onboard requires passphrase input; use --passphrase / --passphrase-file, pipe it via stdin, or run on a TTY",
        super::prompts::prompt_passphrase,
    )
}

pub fn resolve_package_secret(
    value: Option<String>,
    file: Option<String>,
    missing_message: &str,
) -> Result<String> {
    resolve_secret_source_with(
        value,
        file,
        std::io::stdin().is_terminal(),
        "package-secret",
        missing_message,
        || super::prompts::prompt_package_secret().map(|p| p.expose_secret().to_string()),
    )
}

pub fn resolve_required_text<F>(
    value: Option<String>,
    stdin_is_terminal: bool,
    missing_message: &str,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        Some(_) => bail!("value cannot be empty"),
        None if stdin_is_terminal => prompt(),
        None => bail!("{missing_message}"),
    }
}

pub fn resolve_u16_input<F>(
    value: Option<u16>,
    stdin_is_terminal: bool,
    label: &str,
    missing_message: &str,
    prompt: F,
) -> Result<u16>
where
    F: FnOnce() -> Result<u16>,
{
    match value {
        Some(value) if value > 0 => Ok(value),
        Some(_) => bail!("{label} must be greater than zero"),
        None if stdin_is_terminal => prompt(),
        None => bail!("{missing_message}"),
    }
}

pub fn resolve_member_index(
    value: Option<u16>,
    draft: &igloo_shell_core::shell::GeneratedKeysetDraft,
    stdin_is_terminal: bool,
    missing_message: &str,
) -> Result<u16> {
    match value {
        Some(member_idx) => validate_member_index(draft, member_idx),
        None if stdin_is_terminal => super::prompts::prompt_member_index(draft),
        None => bail!("{missing_message}"),
    }
}

pub fn validate_member_index(
    draft: &igloo_shell_core::shell::GeneratedKeysetDraft,
    member_idx: u16,
) -> Result<u16> {
    if draft
        .shares
        .iter()
        .any(|share| share.member_idx == member_idx)
    {
        return Ok(member_idx);
    }
    bail!("member index {member_idx} is not available in this generated keyset")
}

pub fn resolve_keygen_relays(
    relay_urls: Vec<String>,
    stdin_is_terminal: bool,
) -> Result<Vec<String>> {
    if !relay_urls.is_empty() {
        return Ok(relay_urls);
    }
    if stdin_is_terminal {
        return super::prompts::prompt_relay_urls();
    }
    bail!("keygen requires at least one --relay-url when stdin is not a TTY")
}

/// Resolve a (non-passphrase) `String` secret from explicit args, a file,
/// stdin pipe, or a TTY prompt.
///
/// Bucket C C.5: when called from a non-TTY context with no `--value`/
/// `--value-file`, the secret is read from stdin so scripted callers can
/// pipe it in. Callers that need a `Passphrase` should use
/// [`resolve_passphrase_source_with`] instead.
pub fn resolve_secret_source_with<F>(
    value: Option<String>,
    file: Option<String>,
    stdin_is_terminal: bool,
    secret_label: &str,
    missing_message: &str,
    prompt: F,
) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    match (value, file) {
        (Some(value), None) => {
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(value)
        }
        (None, Some(path)) => {
            let value = fs::read_to_string(&path)
                .with_context(|| format!("read {secret_label} file {path}"))?
                .trim_end()
                .to_string();
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(value)
        }
        (None, None) if stdin_is_terminal => {
            let value = prompt()?.trim_end().to_string();
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(value)
        }
        (None, None) => {
            // C.5: stdin is a pipe (not a TTY) and no explicit flag was
            // given — consume one line from stdin. This is the documented
            // scripted-call mode that replaced the retired
            // env-var passphrase invocation style.
            let value = read_secret_from_stdin(secret_label, missing_message)?;
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(value)
        }
        (Some(_), Some(_)) => unreachable!("clap enforces secret source conflicts"),
    }
}

/// Same shape as [`resolve_secret_source_with`] but the prompt + final
/// value live in a [`Passphrase`] so the secret is wiped on drop.
pub fn resolve_passphrase_source_with<F>(
    value: Option<String>,
    file: Option<String>,
    stdin_is_terminal: bool,
    secret_label: &str,
    missing_message: &str,
    prompt: F,
) -> Result<Passphrase>
where
    F: FnOnce() -> Result<Passphrase>,
{
    match (value, file) {
        (Some(value), None) => {
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(Passphrase::new(value))
        }
        (None, Some(path)) => {
            let value = fs::read_to_string(&path)
                .with_context(|| format!("read {secret_label} file {path}"))?
                .trim_end()
                .to_string();
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(Passphrase::new(value))
        }
        (None, None) if stdin_is_terminal => {
            let p = prompt()?;
            if p.expose_secret().is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(p)
        }
        (None, None) => {
            // C.5: stdin is a pipe (not a TTY); read the passphrase from
            // stdin in place of the retired passphrase env var.
            let value = read_secret_from_stdin(secret_label, missing_message)?;
            if value.is_empty() {
                bail!("{secret_label} cannot be empty");
            }
            Ok(Passphrase::new(value))
        }
        (Some(_), Some(_)) => unreachable!("clap enforces secret source conflicts"),
    }
}

/// Read a single line / piped blob from stdin and return its trimmed value.
///
/// Bucket C C.5 helper: callers route here when stdin is a pipe, no
/// explicit `--value` / `--value-file` was given, and no interactive
/// prompt is possible.
fn read_secret_from_stdin(secret_label: &str, missing_message: &str) -> Result<String> {
    let mut buf = String::new();
    let read = std::io::stdin()
        .read_to_string(&mut buf)
        .with_context(|| format!("read {secret_label} from stdin"))?;
    if read == 0 {
        bail!("{missing_message}");
    }
    let trimmed = buf.trim_end_matches(['\n', '\r']).to_string();
    Ok(trimmed)
}

pub fn resolve_rotation_source_passwords(
    document: &RotationWorkspaceDocument,
    stdin_is_terminal: bool,
) -> Result<Vec<String>> {
    document
        .source_packages
        .iter()
        .map(|source| {
            let package_secret = load_secret_from_env(source.package_secret_env.clone())?;
            resolve_secret_source_with(
                package_secret,
                source.package_secret_file.clone(),
                stdin_is_terminal,
                "package-secret",
                &format!(
                    "rotate-keyset generate requires a source package secret for {}; set package_secret_env/package_secret_file in the workspace or run on a TTY",
                    source.package_path
                ),
                || super::prompts::prompt_rotation_source_package_secret(&source.package_path)
                    .map(|p| p.expose_secret().to_string()),
            )
        })
        .collect()
}

pub fn read_package_or_inline(package_or_path: &str) -> Result<String> {
    let path = Path::new(package_or_path);
    if path.exists() {
        return Ok(fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?
            .trim()
            .to_string());
    }
    Ok(package_or_path.to_string())
}

pub fn load_mode(args: &LoadArgs) -> LoadMode {
    if args.start {
        LoadMode::StartAttached
    } else if args.daemon {
        LoadMode::StartBackground
    } else {
        LoadMode::StatusOnly
    }
}

/// Resolve a passphrase indirection that came in via an `--xxx-env` flag.
///
/// Bucket C C.5: the legacy global passphrase env contract is gone, but
/// a few specific subcommands still accept a user-named env var (e.g.
/// `profile backup --passphrase-env MY_VAR`) so the operator can choose a
/// one-off variable name. Returns `Ok(None)` when no env indirection was
/// requested.
pub fn load_secret_from_env(env_name: Option<String>) -> Result<Option<String>> {
    match env_name {
        Some(name) => Ok(Some(
            std::env::var(&name).map_err(|_| anyhow::anyhow!("missing env var {name}"))?,
        )),
        None => Ok(None),
    }
}

/// Like [`load_secret_from_env`] but wraps the resulting string in a
/// [`Passphrase`] when present.
pub fn load_passphrase_from_env(env_name: Option<String>) -> Result<Option<Passphrase>> {
    Ok(load_secret_from_env(env_name)?.map(Passphrase::new))
}

pub fn require_env_secret(env_name: Option<String>, label: &str) -> Result<String> {
    load_secret_from_env(env_name)?
        .ok_or_else(|| anyhow!("{label} must be provided through an environment variable"))
}
