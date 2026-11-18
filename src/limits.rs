//! Operator-tunable stage limits.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static STAGE_TIMEOUT: OnceLock<Duration> = OnceLock::new();
static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_stage_timeout(timeout: Option<Duration>) {
    if let Some(timeout) = timeout {
        let _ = STAGE_TIMEOUT.set(timeout);
    }
}

pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Use the operator's absolute stage timeout when one was supplied.
pub fn stage(default: Duration) -> Duration {
    STAGE_TIMEOUT
        .get()
        .copied()
        .unwrap_or(default)
        .max(Duration::from_millis(1))
}

pub struct Span {
    label: &'static str,
    started: Instant,
}

impl Span {
    pub fn new(label: &'static str) -> Self {
        if verbose() {
            eprintln!("  [..] {label}");
        }
        Self { label, started: Instant::now() }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if verbose() {
            eprintln!("  [ok] {} {:.2}s", self.label, self.started.elapsed().as_secs_f64());
        }
    }
}
