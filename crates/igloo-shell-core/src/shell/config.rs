use anyhow::Result;
pub use bifrost_profile::{FallbackUnlockMode, KeyringPreference, RelayProfile, ShellConfig};
use bifrost_profile::{
    load_relay_profiles_file, load_shell_config_file, save_relay_profiles_file,
    save_shell_config_file,
};

use super::ShellPaths;

pub fn load_shell_config(paths: &ShellPaths) -> Result<ShellConfig> {
    load_shell_config_file(&paths.config_path)
}

pub fn save_shell_config(paths: &ShellPaths, config: &ShellConfig) -> Result<()> {
    save_shell_config_file(&paths.config_path, config)
}

pub fn load_relay_profiles(paths: &ShellPaths) -> Result<Vec<RelayProfile>> {
    load_relay_profiles_file(&paths.relay_profiles_path)
}

pub fn save_relay_profiles(paths: &ShellPaths, profiles: &[RelayProfile]) -> Result<()> {
    save_relay_profiles_file(&paths.relay_profiles_path, profiles)
}
