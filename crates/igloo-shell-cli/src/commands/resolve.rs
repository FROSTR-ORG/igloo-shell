use super::super::*;

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
        super::prompts::prompt_onboarding_secret,
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

pub fn resolve_passphrase(value: Option<String>, file: Option<String>) -> Result<String> {
    resolve_secret_source_with(
        value,
        file,
        std::io::stdin().is_terminal(),
        "encrypted-profile-secret",
        "onboard requires passphrase input; use --passphrase / --passphrase-file, or run on a TTY",
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
        super::prompts::prompt_package_secret,
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
        (None, None) => bail!("{missing_message}"),
        (Some(_), Some(_)) => unreachable!("clap enforces secret source conflicts"),
    }
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
                || super::prompts::prompt_rotation_source_package_secret(&source.package_path),
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

pub fn load_secret_from_env(env_name: Option<String>) -> Result<Option<String>> {
    match env_name {
        Some(name) => Ok(Some(
            std::env::var(&name).map_err(|_| anyhow::anyhow!("missing env var {name}"))?,
        )),
        None => Ok(None),
    }
}

pub fn require_env_secret(env_name: Option<String>, label: &str) -> Result<String> {
    load_secret_from_env(env_name)?
        .ok_or_else(|| anyhow!("{label} must be provided through an environment variable"))
}
