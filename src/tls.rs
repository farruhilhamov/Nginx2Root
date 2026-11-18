//! TLS 1.3 transport: OpenSSL owns the handshake; after it yields the client
//! traffic secret we own the record layer so multi-gigabyte flights can be
//! streamed without buffering and with exact TLS record boundaries.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// macOS has no `MSG_NOSIGNAL`; SIGPIPE is ignored process-wide instead.
#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: libc::c_int = 0;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use openssl::ssl::{
    SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion,
};
use sha2::{Sha256, Sha384};

pub const TLS_RECORD_PLAINTEXT: usize = 16384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aes256GcmSha384,
    Aes128GcmSha256,
    ChaCha20Poly1305Sha256,
}

impl Cipher {
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(match name {
            "TLS_AES_256_GCM_SHA384" => Cipher::Aes256GcmSha384,
            "TLS_AES_128_GCM_SHA256" => Cipher::Aes128GcmSha256,
            "TLS_CHACHA20_POLY1305_SHA256" => Cipher::ChaCha20Poly1305Sha256,
            other => bail!("unsupported negotiated cipher: {other}"),
        })
    }

    pub fn key_len(self) -> usize {
        match self {
            Cipher::Aes128GcmSha256 => 16,
            Cipher::Aes256GcmSha384 | Cipher::ChaCha20Poly1305Sha256 => 32,
        }
    }

    pub fn hash_len(self) -> usize {
        match self {
            Cipher::Aes256GcmSha384 => 48,
            Cipher::Aes128GcmSha256 | Cipher::ChaCha20Poly1305Sha256 => 32,
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Cipher::Aes256GcmSha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("hmac key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            _ => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    #[allow(deprecated)]
    fn seal(self, key: &[u8], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Aes256GcmSha384 => {
                let cipher = Aes256Gcm::new_from_slice(key).expect("key length");
                cipher
                    .encrypt(Nonce::from_slice(nonce), Payload { msg, aad })
                    .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))
            }
            Cipher::Aes128GcmSha256 => {
                let cipher = Aes128Gcm::new_from_slice(key).expect("key length");
                cipher
                    .encrypt(Nonce::from_slice(nonce), Payload { msg, aad })
                    .map_err(|_| anyhow::anyhow!("AES-128-GCM encryption failed"))
            }
            Cipher::ChaCha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key length");
                cipher
                    .encrypt(nonce.into(), Payload { msg, aad })
                    .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed"))
            }
        }
    }
}

/// HKDF-Expand-Label as used by TLS 1.3 (`context` is always empty here).
pub fn hkdf_label(secret: &[u8], label: &[u8], size: usize, cipher: Cipher) -> Vec<u8> {
    let mut full = b"tls13 ".to_vec();
    full.extend_from_slice(label);
    let mut info = Vec::with_capacity(full.len() + 4);
    info.extend_from_slice(&(size as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(0);

    let mut output = Vec::with_capacity(size + cipher.hash_len());
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while output.len() < size {
        let mut message = previous.clone();
        message.extend_from_slice(&info);
        message.push(counter);
        previous = cipher.hmac(secret, &message);
        output.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    output.truncate(size);
    output
}

#[derive(Clone)]
pub struct RecordWriter {
    cipher: Cipher,
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: [u8; 12],
    pub sequence: u64,
    pub records: u64,
    pub app_bytes: u64,
    pub wire_bytes: u64,
}

impl RecordWriter {
    pub fn new(secret: Vec<u8>, cipher: Cipher) -> Result<Self> {
        if secret.len() != cipher.hash_len() {
            bail!(
                "traffic secret is {} bytes, cipher {} needs {}",
                secret.len(),
                cipher.key_len(),
                cipher.hash_len()
            );
        }
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&hkdf_label(&secret, b"iv", 12, cipher));
        let key = hkdf_label(&secret, b"key", cipher.key_len(), cipher);
        Ok(Self { cipher, secret, key, iv, sequence: 0, records: 0, app_bytes: 0, wire_bytes: 0 })
    }

    /// Encrypt one TLS 1.3 record. `inner` is the real content type (23 for
    /// application data, 22 for a KeyUpdate handshake message).
    pub fn record(&mut self, plaintext: &[u8], inner: u8) -> Vec<u8> {
        let record = self.encrypt_record(self.sequence, plaintext, inner);
        self.sequence += 1;
        self.records += 1;
        self.app_bytes += plaintext.len() as u64;
        self.wire_bytes += record.len() as u64;
        record
    }

    /// Encrypt at an explicit sequence number without touching the ledger, so
    /// independent plaintext slices can be encoded in parallel.
    pub fn encrypt_record(&self, sequence: u64, plaintext: &[u8], inner: u8) -> Vec<u8> {
        // Key and IV are derived once per traffic secret, not per record: the
        // bulk phase emits millions of 16 KiB records.
        let mut nonce = self.iv;
        let seq = sequence.to_be_bytes();
        for index in 0..8 {
            nonce[4 + index] ^= seq[index];
        }
        let ciphertext_len = plaintext.len() + 1 + 16;
        let header = [
            0x17,
            0x03,
            0x03,
            (ciphertext_len >> 8) as u8,
            ciphertext_len as u8,
        ];
        let mut message = Vec::with_capacity(plaintext.len() + 1);
        message.extend_from_slice(plaintext);
        message.push(inner);
        let sealed = self
            .cipher
            .seal(&self.key, &nonce, &header, &message)
            .expect("record encryption");
        let mut record = Vec::with_capacity(5 + ciphertext_len);
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        record
    }

    /// Advance the client traffic secret after a KeyUpdate record.
    pub fn update(&mut self) {
        self.secret = hkdf_label(
            &self.secret,
            b"traffic upd",
            self.cipher.hash_len(),
            self.cipher,
        );
        self.iv.copy_from_slice(&hkdf_label(&self.secret, b"iv", 12, self.cipher));
        self.key = hkdf_label(&self.secret, b"key", self.cipher.key_len(), self.cipher);
        self.sequence = 0;
    }

    /// Send one TLS 1.3 KeyUpdate handshake message, then advance the secret.
    /// The record plaintext is the handshake message itself:
    /// `KeyUpdate(18) length=000001 body=01 (update_requested)`.
    pub fn key_update(&mut self) -> Vec<u8> {
        let record = self.record(&[0x18, 0x00, 0x00, 0x01, 0x01], 22);
        self.update();
        record
    }
}

pub struct RawTransport {
    pub tcp: TcpStream,
    inbound: Vec<u8>,
    /// Set when OpenSSL writes through the transport after takeover.
    pub openssl_wrote: bool,
    pub allow_raw_write: bool,
}

impl RawTransport {
    pub fn new(tcp: TcpStream) -> Self {
        Self { tcp, inbound: Vec::new(), openssl_wrote: false, allow_raw_write: false }
    }
}

impl Read for RawTransport {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if !self.inbound.is_empty() {
            let n = out.len().min(self.inbound.len());
            out[..n].copy_from_slice(&self.inbound[..n]);
            self.inbound.drain(..n);
            return Ok(n);
        }
        self.tcp.read(out)
    }
}

impl Write for RawTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.allow_raw_write {
            self.openssl_wrote = true;
        }
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

pub trait Transport {
    fn recv(&mut self, max: usize) -> io::Result<Vec<u8>>;
    fn send(&mut self, plaintext: &[u8]) -> io::Result<()>;
    fn send_event(&mut self, plaintext: &[u8]) -> io::Result<()>;
    fn set_read_timeout(&mut self, timeout: Duration);
    fn set_backpressure_window(&mut self, bytes: i32) -> io::Result<()>;
    fn take_openssl_write(&mut self) -> bool {
        false
    }
    fn close(&mut self);
}

fn tls_context() -> Result<openssl::ssl::SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_verify(SslVerifyMode::NONE);
    // ALPN wire format: one length-prefixed protocol name.
    builder.set_alpn_protos(b"\x02h2")?;
    Ok(builder)
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

pub struct RawTls {
    stream: SslStream<RawTransport>,
    pub writer: RecordWriter,
    #[allow(dead_code)]
    pub cipher_name: String,
}

impl RawTls {
    pub fn connect(tcp: TcpStream, host: &str) -> Result<Self> {
        let secret_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let mut builder = tls_context()?;
        {
            let slot = Arc::clone(&secret_slot);
            builder.set_keylog_callback(move |_, line| {
                if let Some(rest) = line.strip_prefix("CLIENT_TRAFFIC_SECRET_0 ") {
                    if let Some((_, secret)) = rest.split_once(' ') {
                        if let Ok(mut guard) = slot.lock() {
                            *guard = Some(secret.to_string());
                        }
                    }
                }
            });
        }
        let connector = builder.build();
        let ssl = connector.configure()?.into_ssl(host)?;
        let mut stream = SslStream::new(ssl, RawTransport::new(tcp))?;
        if let Err(error) = stream.connect() {
            let text = error.to_string();
            if text.contains("no application protocol") {
                bail!("target does not negotiate HTTP/2 (ALPN h2) over TLS");
            }
            return Err(anyhow::Error::new(error).context("TLS 1.3 handshake"));
        }
        if stream.ssl().selected_alpn_protocol() != Some(b"h2".as_slice()) {
            bail!("target did not negotiate ALPN h2");
        }
        let cipher_name = stream
            .ssl()
            .current_cipher()
            .map(|cipher| cipher.name().to_string())
            .context("TLS cipher is not set")?;
        let secret_hex = secret_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("keylog callback poisoned"))?
            .clone()
            .context("OpenSSL did not log CLIENT_TRAFFIC_SECRET_0")?;
        let secret = hex::decode(secret_hex.trim()).context("keylog secret is not hex")?;
        let writer = RecordWriter::new(secret, Cipher::from_name(&cipher_name)?)?;
        // Handshake records went through the transport; from here on any
        // OpenSSL write would bypass the explicit record layer.
        stream.get_mut().openssl_wrote = false;
        Ok(Self { stream, writer, cipher_name })
    }

    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.stream.get_ref().tcp.as_raw_fd()
    }

    fn write_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.get_mut().allow_raw_write = true;
        let result = self.stream.get_mut().write_all(bytes);
        self.stream.get_mut().allow_raw_write = false;
        result
    }

    /// True if OpenSSL wrote a record behind the explicit record layer.
    pub fn take_openssl_write(&mut self) -> bool {
        let wrote = self.stream.get_mut().openssl_wrote;
        self.stream.get_mut().openssl_wrote = false;
        wrote
    }

    /// Append already-encrypted TLS records to the socket (bulk sender).
    pub fn write_encrypted(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.write_raw(bytes)
    }

    /// Send one precomputed flight in a single socket write.
    pub fn send_flight(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut flight = Vec::with_capacity(plaintext.len() + plaintext.len() / 8192 + 64);
        for chunk in plaintext.chunks(TLS_RECORD_PLAINTEXT) {
            flight.extend_from_slice(&self.writer.record(chunk, 23));
        }
        self.write_raw(&flight)
    }

    pub fn send_key_updates(&mut self, count: usize) -> io::Result<Vec<u8>> {
        let mut flight = Vec::with_capacity(count * 27);
        for _ in 0..count {
            flight.extend_from_slice(&self.writer.key_update());
        }
        Ok(flight)
    }

    /// Send a fixed flight without reading, preserving server backpressure.
    /// After `hold`, restore the receive window and buffer ciphertext if the
    /// peer needs TCP progress to finish consuming the flight.
    pub fn send_backpressured(
        &mut self,
        flight: &[u8],
        receive_window: i32,
        hold: Duration,
        timeout: Duration,
    ) -> Result<()> {
        let started = Instant::now();
        let release_at = started + hold;
        let deadline = started + timeout;
        let fd = self.raw_fd();
        self.stream.get_ref().tcp.set_nonblocking(true)?;
        let mut sent = 0usize;
        let mut released = false;
        let mut drained = 0usize;
        let result = (|| -> Result<()> {
            while sent < flight.len() {
                let now = Instant::now();
                if now >= deadline {
                    bail!("bootstrap TLS upload timed out at {sent}/{}", flight.len());
                }
                if !released && now >= release_at {
                    self.set_backpressure_window(receive_window)?;
                    released = true;
                }
                let mut wait = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
                if !released {
                    wait = wait.min(
                        (release_at.saturating_duration_since(now)).as_millis() as i32,
                    );
                }
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT | if released { libc::POLLIN } else { 0 },
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut pfd, 1, wait.max(1)) };
                if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error.into());
                }
                if pfd.revents & libc::POLLOUT != 0 {
                    let written = unsafe {
                        libc::send(
                            fd,
                            flight[sent..].as_ptr() as *const libc::c_void,
                            flight.len() - sent,
                            SEND_FLAGS,
                        )
                    };
                    if written > 0 {
                        sent += written as usize;
                    } else if written == 0 {
                        bail!("peer closed during bootstrap TLS upload");
                    } else {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::WouldBlock {
                            return Err(error.into());
                        }
                    }
                }
                if released && pfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    let mut buffer = vec![0u8; 262_144];
                    let count = unsafe {
                        libc::recv(
                            fd,
                            buffer.as_mut_ptr() as *mut libc::c_void,
                            buffer.len(),
                            0,
                        )
                    };
                    if count > 0 {
                        drained += count as usize;
                        self.stream.get_mut().inbound.extend_from_slice(
                            &buffer[..count as usize],
                        );
                    } else if count == 0 {
                        bail!("peer closed during bootstrap TLS upload");
                    }
                }
            }
            if !released {
                std::thread::sleep(hold);
                self.set_backpressure_window(receive_window)?;
            }
            Ok(())
        })();
        self.stream.get_ref().tcp.set_nonblocking(false)?;
        result?;
        let _ = drained;
        Ok(())
    }
}

impl Transport for RawTls {
    fn recv(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; max];
        let count = self.stream.read(&mut buffer)?;
        buffer.truncate(count);
        Ok(buffer)
    }

    fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        if plaintext.len() <= TLS_RECORD_PLAINTEXT {
            let record = self.writer.record(plaintext, 23);
            return self.write_raw(&record);
        }
        self.send_flight(plaintext)
    }

    fn send_event(&mut self, plaintext: &[u8]) -> io::Result<()> {
        self.send_flight(plaintext)
    }

    fn set_read_timeout(&mut self, timeout: Duration) {
        let _ = self.stream.get_ref().tcp.set_read_timeout(Some(timeout));
    }

    fn set_backpressure_window(&mut self, bytes: i32) -> io::Result<()> {
        let tcp = &self.stream.get_ref().tcp;
        set_socket_window(tcp, bytes)
    }

    fn take_openssl_write(&mut self) -> bool {
        let wrote = self.stream.get_mut().openssl_wrote;
        self.stream.get_mut().openssl_wrote = false;
        wrote
    }

    fn close(&mut self) {
        // Closing TCP is enough after explicit-key takeover; a close_notify
        // would create an untracked record.
        let _ = self.stream.get_ref().tcp.shutdown(std::net::Shutdown::Both);
    }
}

pub struct StandardTls {
    stream: SslStream<TcpStream>,
}

impl StandardTls {
    pub fn connect(tcp: TcpStream, host: &str) -> Result<Self> {
        let connector = tls_context()?.build();
        let ssl = connector.configure()?.into_ssl(host)?;
        let mut stream = SslStream::new(ssl, tcp)?;
        stream.connect().context("auxiliary TLS handshake")?;
        if stream.ssl().selected_alpn_protocol() != Some(b"h2".as_slice()) {
            bail!("auxiliary target did not negotiate ALPN h2");
        }
        stream.get_ref().set_read_timeout(Some(Duration::from_millis(70)))?;
        Ok(Self { stream })
    }
}

impl Transport for StandardTls {
    fn recv(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; max];
        let count = self.stream.read(&mut buffer)?;
        buffer.truncate(count);
        Ok(buffer)
    }

    fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        self.stream.write_all(plaintext)
    }

    fn send_event(&mut self, plaintext: &[u8]) -> io::Result<()> {
        self.stream.write_all(plaintext)
    }

    fn set_read_timeout(&mut self, timeout: Duration) {
        let _ = self.stream.get_ref().set_read_timeout(Some(timeout));
    }

    fn set_backpressure_window(&mut self, bytes: i32) -> io::Result<()> {
        set_socket_window(self.stream.get_ref(), bytes)
    }

    fn close(&mut self) {
        let _ = self.stream.get_ref().shutdown(std::net::Shutdown::Both);
    }
}

/// Apply the reference exploit's TCP backpressure knobs. `bytes` is the
/// receive buffer and window clamp; the kernel rounds it up.
pub fn set_socket_window(tcp: &TcpStream, bytes: i32) -> io::Result<()> {
    let value: libc::c_int = bytes;
    let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    #[allow(unused_mut)]
    let mut options = vec![(libc::SOL_SOCKET, libc::SO_RCVBUF)];
    // Linux can also clamp the advertised TCP window; macOS cannot and uses
    // SO_RCVBUF alone for backpressure.
    #[cfg(target_os = "linux")]
    options.push((libc::IPPROTO_TCP, libc::TCP_WINDOW_CLAMP));
    for (level, option) in options {
        let rc = unsafe {
            libc::setsockopt(
                tcp.as_raw_fd(),
                level,
                option,
                &value as *const _ as *const libc::c_void,
                size,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Set the advertised MSS, matching the calibrated transport schedule.
pub fn set_max_segment(tcp: &TcpStream, bytes: i32) -> io::Result<()> {
    let value: libc::c_int = bytes;
    let rc = unsafe {
        libc::setsockopt(
            tcp.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_receive_buffer(tcp: &TcpStream, bytes: i32) -> io::Result<()> {
    let value: libc::c_int = bytes;
    let rc = unsafe {
        libc::setsockopt(
            tcp.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc5869_expand_label() {
        // Expected values produced with the reference hkdf_label implementation
        // (see the design doc §8); pinned so a wrong label/context fails here.
        let secret = [1u8; 32];
        assert_eq!(
            hex::encode(hkdf_label(&secret, b"key", 32, Cipher::Aes128GcmSha256)),
            "b8ac2fa5d3e65e2a50100e28dd1e5a1e9c69d4b54ab0e574013c4884a23f67ad"
        );
        assert_eq!(
            hex::encode(hkdf_label(&secret, b"iv", 12, Cipher::Aes128GcmSha256)),
            "5fae678ed5298223de915447"
        );
    }

    #[test]
    fn record_header_and_ledger() {
        let mut w = RecordWriter::new(vec![1u8; 32], Cipher::Aes128GcmSha256).unwrap();
        let record = w.record(b"abc", 23);
        assert_eq!(&record[..5], &[0x17, 0x03, 0x03, 0x00, 0x14]);
        assert_eq!(record.len(), 5 + 3 + 1 + 16);
        assert_eq!((w.sequence, w.records, w.app_bytes, w.wire_bytes), (1, 1, 3, 25));
    }

    #[test]
    fn key_update_resets_sequence() {
        let mut w = RecordWriter::new(vec![2u8; 48], Cipher::Aes256GcmSha384).unwrap();
        let first = w.record(b"abc", 23);
        let update = w.key_update();
        assert_eq!(update[0], 0x17);
        // The KeyUpdate record used the old key at sequence 0; the new key
        // starts again at sequence 0.
        assert_eq!(w.sequence, 0);
        assert_eq!(w.records, 2);
        let second = w.record(b"abc", 23);
        // New key => different ciphertext for the same plaintext and nonce.
        assert_ne!(first[5..], second[5..]);
    }

    #[test]
    fn cipher_names() {
        assert_eq!(Cipher::from_name("TLS_AES_256_GCM_SHA384").unwrap(), Cipher::Aes256GcmSha384);
        assert_eq!(Cipher::from_name("TLS_AES_128_GCM_SHA256").unwrap(), Cipher::Aes128GcmSha256);
        assert_eq!(
            Cipher::from_name("TLS_CHACHA20_POLY1305_SHA256").unwrap(),
            Cipher::ChaCha20Poly1305Sha256
        );
        assert!(Cipher::from_name("TLS_AES_128_CCM_SHA256").is_err());
    }
}
