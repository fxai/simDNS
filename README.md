# simdns — DNS Telemetry Emulation Server

A purple-team **detection-engineering harness** that generates controlled,
reproducible, highly tunable DNS artifacts so SOC/detection engineers can
validate SIEM/EDR rules against DNS-tunneling and C2-style patterns.

> **This is a test harness, not an implant.** It contains no evasion,
> obfuscation, domain-fronting, or anti-analysis logic. Its goal is to produce
> *detectable* ground-truth traffic. Run it only against zones and labs you are
> authorised to test.

## What it does

- Acts as an **authoritative responder** for a single delegated zone; every
  out-of-zone query is `REFUSED`.
- Models an **inbound channel** (data in subdomain labels; base32/hex/base64url)
  and an **outbound channel** (data in TXT/A/AAAA/CNAME/NULL record sets).
- Exposes **signature-shaping knobs**: temporal jitter, record-type mix, payload
  density, and NXDOMAIN/SERVFAIL failure rates.
- Emits **structured JSON telemetry** per query and optional **HTTP metrics**
  (Prometheus + JSON) for timestamp correlation with SOC alerts.
- Is robust by construction: malformed packets yield `FORMERR` (never a panic),
  memory is bounded (session cap + TCP limits), and shutdown is graceful.

## Build

Requires a Rust stable toolchain (1.75+):

```bash
cargo build --release
# binary at target/release/simdns  (single static-ish binary)
cargo test            # unit tests for encoding, sessions, zone, profile
```

## Run

```bash
# defaults (binds 0.0.0.0:53 — needs privileges)
sudo ./target/release/simdns

# unprivileged local test with metrics
./target/release/simdns --port 5353 --zone test.local --metrics-addr 127.0.0.1:9100

# a pre-built detection scenario
./target/release/simdns --config scenarios/high-entropy-long-label.toml
```

Quick smoke test:

```bash
dig @127.0.0.1 -p 5353 TXT nbswy3dp.0.sess01.test.local +norecurse
dig @127.0.0.1 -p 5353 A   example.org +norecurse        # -> REFUSED
curl -s 127.0.0.1:9100/metrics.json
```

## Configuration

All knobs live in TOML; see [`config.example.toml`](config.example.toml) for the
fully-annotated template. CLI flags (`--bind`, `--port`, `--zone`, `--encoding`,
`--metrics-addr`, `--log-format`, `--log-decoded-payload`) override file values.
Verbosity via `RUST_LOG` (e.g. `RUST_LOG=simdns=debug`).

## Documentation

- [docs/WIRE_FORMAT.md](docs/WIRE_FORMAT.md) — the client/server wire contract.
- [docs/DELEGATION.md](docs/DELEGATION.md) — NS delegation setup.
- [docs/SCENARIOS.md](docs/SCENARIOS.md) — pre-built detection scenarios in
  [`scenarios/`](scenarios/).

## Layout

```
src/
  main.rs        CLI, wiring, listeners, sweeper, shutdown
  config.rs      TOML model + defaults + validation
  encoding.rs    base32 / hex / base64url label codecs
  zone.rs        authority check + data-label extraction
  session.rs     TTL-evicted, capacity-capped session map
  profile.rs     signature shaping (jitter, record mix, failure rates)
  handler.rs     parse -> authorise -> shape -> build response
  metrics.rs     atomic counters + axum endpoint
  telemetry.rs   tracing (JSON/pretty) init
  net/           UDP + TCP listeners (framing, bounds, jitter)
```

## License

MIT.
