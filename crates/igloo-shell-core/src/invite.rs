use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use bifrost_codec::{parse_share_package, wire::SharePackageWire};
use frostr_utils::{
    assemble_onboarding_package, decode_invite_token, decode_onboarding_package,
    encode_onboarding_package,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use serde::Serialize;

pub fn run_invite_command(args: &[String]) -> Result<()> {
    let Some(cmd) = args.first().map(String::as_str) else {
        return Ok(());
    };

    match cmd {
        "assemble" => run_invite_assemble_command(&args[1..]),
        "accept" => run_invite_accept_command(&args[1..]),
        "help" | "--help" | "-h" => Ok(()),
        _ => Ok(()),
    }
}

fn run_invite_assemble_command(args: &[String]) -> Result<()> {
    let token = required_arg_value(args, "--token")?;
    let share_path = PathBuf::from(required_arg_value(args, "--share")?);
    let (password, generated) = resolve_password(args, true)?;

    let token = decode_invite_token(&token).context("decode invite token")?;
    let share_raw =
        fs::read_to_string(&share_path).with_context(|| format!("read {}", share_path.display()))?;
    let share = parse_share_package(&share_raw).context("parse share package")?;
    let package = assemble_onboarding_package(&token, share).context("assemble onboarding")?;
    let encoded = encode_onboarding_package(&package, &password).context("encode onboarding")?;

    if generated {
        eprintln!("generated password: {password}");
    }
    println!("{encoded}");
    Ok(())
}

fn run_invite_accept_command(args: &[String]) -> Result<()> {
    let package = args
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("missing onboarding package"))?;
    let (password, _) = resolve_password(&args[1..], false)?;
    let decoded =
        decode_onboarding_package(&package, Some(password.as_str())).context("decode onboarding")?;
    let payload = DecodedInviteJson::from_package(decoded)?;
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn resolve_password(args: &[String], allow_generate: bool) -> Result<(String, bool)> {
    if let Some(var_name) = arg_value(args, "--password-env") {
        let value =
            std::env::var(&var_name).with_context(|| format!("missing env var {var_name}"))?;
        return Ok((value, false));
    }
    if let Some(path) = arg_value(args, "--password-file") {
        let value =
            fs::read_to_string(&path).with_context(|| format!("read password file {path}"))?;
        return Ok((value.trim_end().to_string(), false));
    }
    if has_flag(args, "--password-stdin") {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("read password from stdin")?;
        return Ok((buffer.trim_end().to_string(), false));
    }
    if allow_generate && has_flag(args, "--generate-password") {
        return Ok((generate_password(), true));
    }

    Err(anyhow!(
        "one of --password-env, --password-file, --password-stdin, or --generate-password is required"
    ))
}

fn generate_password() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == key {
            return args.get(i + 1).cloned();
        }
    }
    None
}

fn required_arg_value(args: &[String], key: &str) -> Result<String> {
    arg_value(args, key).ok_or_else(|| anyhow!("missing value for {key}"))
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

#[derive(Debug, Serialize)]
struct DecodedInviteJson {
    share: SharePackageWire,
    share_pubkey32: String,
    peer_pk_xonly: String,
    relays: Vec<String>,
    challenge_hex32: Option<String>,
    created_at: Option<u64>,
    expires_at: Option<u64>,
}

impl DecodedInviteJson {
    fn from_package(pkg: frostr_utils::OnboardingPackage) -> Result<Self> {
        let secret = k256::SecretKey::from_slice(&pkg.share.seckey)
            .map_err(|e| anyhow!("invalid share seckey: {e}"))?;
        let point = secret.public_key().to_encoded_point(true);
        Ok(Self {
            share: SharePackageWire::from(pkg.share),
            share_pubkey32: hex::encode(&point.as_bytes()[1..]),
            peer_pk_xonly: hex::encode(pkg.peer_pk),
            relays: pkg.relays,
            challenge_hex32: pkg.challenge.map(hex::encode),
            created_at: pkg.created_at,
            expires_at: pkg.expires_at,
        })
    }
}
