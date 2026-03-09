use anyhow::Result;
use igloo_shell_core::shell::ShellPaths;
use igloo_shell_core::tui;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut profile = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("Usage: igloo-shell-tui [--profile <PROFILE>]");
                return Ok(());
            }
            "--profile" => {
                profile = args.next();
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--profile=") {
                    profile = Some(value.to_string());
                }
            }
        }
    }
    let paths = ShellPaths::resolve()?;
    tui::run_tui(&paths, profile).await
}
