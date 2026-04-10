use super::super::*;

pub fn handle_keys(command: KeyCommands) -> Result<()> {
    match command {
        KeyCommands::Convert { from, value } => print_json(&convert_key(&from, &value)?),
    }
}

fn convert_key(from: &str, value: &str) -> Result<serde_json::Value> {
    match from {
        "hex-private" => {
            let secret = SecretKey::from_hex(strip_hex_prefix(value))?;
            let public = Keys::new(secret.clone()).public_key();
            Ok(serde_json::json!({
                "input": {
                    "kind": "hex-private",
                    "value": secret.to_secret_hex(),
                },
                "outputs": {
                    "nsec": secret.to_bech32()?,
                    "public_hex": public.to_hex(),
                    "npub": public.to_bech32()?,
                }
            }))
        }
        "nsec" => {
            let secret = SecretKey::from_bech32(value)?;
            let public = Keys::new(secret.clone()).public_key();
            Ok(serde_json::json!({
                "input": {
                    "kind": "nsec",
                    "value": value,
                },
                "outputs": {
                    "private_hex": secret.to_secret_hex(),
                    "public_hex": public.to_hex(),
                    "npub": public.to_bech32()?,
                }
            }))
        }
        "hex-public" => {
            let public = PublicKey::from_hex(strip_hex_prefix(value))?;
            Ok(serde_json::json!({
                "input": {
                    "kind": "hex-public",
                    "value": public.to_hex(),
                },
                "outputs": {
                    "npub": public.to_bech32()?,
                }
            }))
        }
        "npub" => {
            let public = PublicKey::from_bech32(value)?;
            Ok(serde_json::json!({
                "input": {
                    "kind": "npub",
                    "value": value,
                },
                "outputs": {
                    "public_hex": public.to_hex(),
                }
            }))
        }
        _ => bail!(
            "unsupported key input kind {from}; expected hex-private, nsec, hex-public, or npub"
        ),
    }
}

fn strip_hex_prefix(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}
