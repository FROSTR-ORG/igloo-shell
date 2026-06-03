use super::super::*;
use bifrost_core::secret::Passphrase;

/// Prompt the operator for a hidden secret, returning a [`Passphrase`].
///
/// Bucket C C.3: the secret leaves the `String` accumulator buffer
/// immediately by being moved into `Passphrase`, which zeroizes on drop and
/// keeps the buffer out of `Debug` output.
pub fn prompt_hidden_secret(lines: &[&str], prompt: &str) -> Result<Passphrase> {
    for line in lines {
        println!("{line}");
    }
    print!("{prompt}: ");
    std::io::Write::flush(&mut std::io::stdout()).context("flush secret prompt")?;

    enable_raw_mode().context("enable raw mode for secret prompt")?;
    let mut password = String::new();
    let result: Result<()> = loop {
        match read().context("read secret input")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char(c) => password.push(c),
                KeyCode::Backspace => {
                    password.pop();
                }
                _ => {}
            },
            _ => {}
        }
    };
    let disable_result = disable_raw_mode().context("disable raw mode for secret prompt");
    println!();
    result?;
    disable_result?;

    if password.is_empty() {
        bail!("secret input cannot be empty");
    }
    Ok(Passphrase::new(password))
}

pub fn prompt_profile_label() -> Result<String> {
    loop {
        println!("Choose a name for this profile before entering any secrets.");
        println!("This label will be shown in profile selection and status output.");
        print!("Profile name: ");
        std::io::Write::flush(&mut std::io::stdout()).context("flush profile name prompt")?;

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("read profile name")?;
        let value = input.trim().to_string();
        if !value.is_empty() {
            return Ok(value);
        }
        println!("Profile name cannot be empty.");
    }
}

pub fn prompt_onboarding_secret() -> Result<Passphrase> {
    prompt_hidden_secret(
        &[
            "This onboarding package is encrypted.",
            "Type the onboarding secret now to decrypt the package input.",
        ],
        "Onboarding secret",
    )
}

pub fn prompt_passphrase() -> Result<Passphrase> {
    loop {
        let secret = prompt_hidden_secret(
            &[
                "This import will store secrets in your local encrypted profile store.",
                "Type a passphrase now to encrypt imported local secrets on this device.",
            ],
            "Passphrase",
        )?;
        let confirm = prompt_hidden_secret(
            &["Retype the passphrase to confirm your input."],
            "Confirm passphrase",
        )?;
        if secret.expose_secret() == confirm.expose_secret() {
            // `confirm` drops here, zeroizing its buffer.
            return Ok(secret);
        }
        println!("Passphrases did not match. Please try again.");
    }
}

pub fn prompt_load_passphrase() -> Result<Passphrase> {
    prompt_hidden_secret(
        &[
            "Type the passphrase for the selected profile now.",
            "igloo-shell will use it to unlock the profile on this device.",
        ],
        "Passphrase",
    )
}

pub fn prompt_package_secret() -> Result<Passphrase> {
    prompt_hidden_secret(
        &[
            "This package is encrypted.",
            "Type the package secret now to continue the import or recovery flow.",
        ],
        "Package secret",
    )
}

pub fn prompt_distribution_secret() -> Result<Passphrase> {
    prompt_hidden_secret(
        &[
            "The remaining generated shares will be written as onboarding packages.",
            "Type the onboarding secret that should encrypt those packages.",
        ],
        "Onboarding package secret",
    )
}

pub fn prompt_rotation_source_package_secret(package_path: &str) -> Result<Passphrase> {
    prompt_hidden_secret(
        &[
            "This rotation source package is encrypted.",
            "Type the package secret now to continue the rotation workflow.",
            package_path,
        ],
        "Package secret",
    )
}

pub fn prompt_group_name() -> Result<String> {
    prompt_line(
        &[
            "Create a new local group.",
            "Type the group name that should be used to identify this group and its shares.",
        ],
        "Group name",
    )
}

pub fn prompt_threshold() -> Result<u16> {
    prompt_u16(
        &["Type the signing threshold for the new keyset."],
        "Threshold",
    )
}

pub fn prompt_count() -> Result<u16> {
    prompt_u16(
        &["Type the total member count for the new keyset."],
        "Member count",
    )
}

pub fn prompt_relay_urls() -> Result<Vec<String>> {
    loop {
        let raw = prompt_line(
            &[
                "Type one or more relay URLs for this generated profile.",
                "Use commas to separate multiple relay URLs.",
            ],
            "Relay URLs",
        )?;
        let relays = raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !relays.is_empty() {
            return Ok(relays);
        }
        println!("At least one relay URL is required.");
    }
}

pub fn prompt_member_index(draft: &igloo_shell_core::shell::GeneratedKeysetDraft) -> Result<u16> {
    println!("Select which generated share should stay on this device:");
    for share in &draft.shares {
        println!("  {}: {}", share.member_idx, share.label);
    }
    loop {
        let member_idx = prompt_u16(&[], "Local member index")?;
        match super::resolve::validate_member_index(draft, member_idx) {
            Ok(member_idx) => return Ok(member_idx),
            Err(err) => println!("{err}"),
        }
    }
}

pub fn prompt_line(lines: &[&str], prompt: &str) -> Result<String> {
    for line in lines {
        println!("{line}");
    }
    print!("{prompt}: ");
    std::io::Write::flush(&mut std::io::stdout()).context("flush prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read prompt input")?;
    let value = input.trim().to_string();
    if value.is_empty() {
        bail!("{prompt} cannot be empty");
    }
    Ok(value)
}

pub fn prompt_u16(lines: &[&str], prompt: &str) -> Result<u16> {
    loop {
        match prompt_line(lines, prompt)?.parse::<u16>() {
            Ok(value) if value > 0 => return Ok(value),
            Ok(_) => println!("{prompt} must be greater than zero."),
            Err(_) => println!("{prompt} must be a positive integer."),
        }
    }
}

pub fn prompt_select_profile(paths: &ShellPaths) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("profile load requires a profile id when stdin is not a TTY");
    }
    let profiles = list_profiles(paths)?;
    if profiles.is_empty() {
        bail!("no profiles found; use igloo-shell onboard, import, recover, or keygen first");
    }
    println!("Select a profile to load:");
    for (index, profile) in profiles.iter().enumerate() {
        println!(
            "  {}: {} ({})",
            index + 1,
            profile.label,
            &profile.id[..profile.id.len().min(8)]
        );
    }
    loop {
        let selection = prompt_u16(&[], "Profile number")?;
        let index = usize::from(selection.saturating_sub(1));
        if let Some(profile) = profiles.get(index) {
            return Ok(profile.id.clone());
        }
        println!("Profile number {selection} is not valid.");
    }
}
