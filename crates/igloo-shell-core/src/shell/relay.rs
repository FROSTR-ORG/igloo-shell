use super::*;

pub(crate) async fn probe_relays(relays: &[String]) -> Vec<RelayProbeResult> {
    let mut results = Vec::with_capacity(relays.len());
    for relay in relays {
        let outcome = match connect_async(relay.as_str()).await {
            Ok((stream, _)) => {
                let mut stream = stream;
                let _ = stream.close(None).await;
                RelayProbeResult {
                    relay: relay.clone(),
                    ok: true,
                    error: None,
                }
            }
            Err(err) => RelayProbeResult {
                relay: relay.clone(),
                ok: false,
                error: Some(err.to_string()),
            },
        };
        results.push(outcome);
    }
    results
}

pub fn replace_relay_profile(paths: &ShellPaths, next: RelayProfile) -> Result<()> {
    validate_relay_profile(&next)?;
    let mut profiles = load_relay_profiles(paths)?;
    profiles.retain(|entry| entry.id != next.id);
    profiles.push(next);
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    save_relay_profiles(paths, &profiles)
}

pub fn add_relays(paths: &ShellPaths, profile_id: &str, relays: &[String]) -> Result<()> {
    let mut profiles = load_relay_profiles(paths)?;
    let Some(profile) = profiles.iter_mut().find(|entry| entry.id == profile_id) else {
        bail!("unknown relay profile {profile_id}");
    };
    for relay in relays {
        if !profile.relays.iter().any(|existing| existing == relay) {
            profile.relays.push(relay.clone());
        }
    }
    validate_relay_profile(profile)?;
    save_relay_profiles(paths, &profiles)
}

pub fn remove_relays(paths: &ShellPaths, profile_id: &str, relays: &[String]) -> Result<()> {
    let mut profiles = load_relay_profiles(paths)?;
    let Some(profile) = profiles.iter_mut().find(|entry| entry.id == profile_id) else {
        bail!("unknown relay profile {profile_id}");
    };
    profile
        .relays
        .retain(|relay| !relays.iter().any(|value| value == relay));
    validate_relay_profile(profile)?;
    save_relay_profiles(paths, &profiles)
}

pub fn set_default_relay_profile(paths: &ShellPaths, profile_id: &str) -> Result<()> {
    let profiles = load_relay_profiles(paths)?;
    if !profiles.iter().any(|entry| entry.id == profile_id) {
        bail!("unknown relay profile {profile_id}");
    }
    let mut config = load_shell_config(paths)?;
    config.default_relay_profile_id = Some(profile_id.to_string());
    save_shell_config(paths, &config)
}

pub(crate) fn validate_relay_profile(profile: &RelayProfile) -> Result<()> {
    bifrost_profile::validate_relay_profile(profile)
}
