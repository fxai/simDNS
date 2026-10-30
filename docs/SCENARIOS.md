# Detection Scenario Profiles

Ready-to-run configs live in [`../scenarios/`](../scenarios/). Each isolates one
signal so you can confirm a detection fires on that signal and not on an
incidental one. Run with `./simdns --config scenarios/<file>.toml` (add
`--metrics-addr 127.0.0.1:9100` to correlate counters with alert timestamps).

The *client side* (query rate, label construction) is out of scope here; drive
it with your own emulator or a `dig` loop. Each profile notes what the driver
should do.

---

## 1. High Entropy / Long Label — `high-entropy-long-label.toml`

- **Signal:** Shannon entropy of labels; label/QNAME length; UDP→TCP fallback.
- **Server config:** `base64url` encoding, `txt_payload_bytes = 900` (forces
  `TC=1` on UDP and a TCP retry), slow jitter (800–2500 ms) so volume is *not*
  the trigger.
- **Driver:** send long, maximally-packed labels (near 63 bytes) at a low rate.
- **Expect to detect:** high-entropy-subdomain and long-label rules; a spike in
  TCP DNS and truncated responses.

```bash
./simdns --config scenarios/high-entropy-long-label.toml --metrics-addr 127.0.0.1:9100
dig @127.0.0.1 TXT $(head -c40 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=').0.s1.test-telemetry.example.com
```

## 2. Volumetric / High Frequency — `volumetric-high-frequency.toml`

- **Signal:** queries-per-source rate; unique-subdomain cardinality per window.
- **Server config:** tiny payloads, zero jitter, low TTL (5s) to keep queries
  flowing past caches.
- **Driver:** high-rate loop, each query a unique subdomain and incrementing seq.
- **Expect to detect:** volumetric DNS and high-unique-NXDOMAIN/subdomain rules.

```bash
for i in $(seq 1 5000); do
  dig +short @127.0.0.1 TXT data$i.$i.sess01.test-telemetry.example.com >/dev/null
done
```

## 3. Uncommon Record Type — `uncommon-record-type.toml`

- **Signal:** rare record types (NULL, long CNAME chains); QTYPE/answer-type
  mismatch.
- **Server config:** `honor_qtype = false`, mix `null = 70 / cname = 30`, so the
  server answers with NULL/CNAME regardless of the QTYPE asked.
- **Driver:** ordinary `A`/`TXT` queries are fine — the server still returns the
  uncommon types.
- **Expect to detect:** "uncommon DNS record type" and answer/QTYPE-mismatch rules.

```bash
dig @127.0.0.1 A anything.0.s1.test-telemetry.example.com   # answered NULL/CNAME
dig @127.0.0.1 NULL anything.0.s1.test-telemetry.example.com
```

## 4. NXDOMAIN Scan / Flood — `nxdomain-scan.toml`

- **Signal:** high NXDOMAIN ratio per source (DGA-like / scanning).
- **Server config:** `nxdomain_rate = 0.90`, `servfail_rate = 0.02`.
- **Driver:** steady query stream to varying names.
- **Expect to detect:** NXDOMAIN-ratio and DGA-style rules; `responses_nxdomain`
  climbs on the metrics endpoint.

```bash
for i in $(seq 1 1000); do
  dig +short @127.0.0.1 A r$i.$i.scan01.test-telemetry.example.com >/dev/null
done
curl -s 127.0.0.1:9100/metrics.json
```

---

## Correlating with your SIEM

1. Start simdns with `--metrics-addr` and note the start time.
2. Run the driver; record the exact window.
3. Compare `responses_*`, `answers_*`, `inbound_payload_bytes`, and
   `sessions_created` against your SIEM's alert timestamps and counts.
4. simdns per-query JSON logs (fields: `src_ip`, `qname`, `qtype`, `rcode`,
   `answer_type`, `session_id`, `seq`, `payload_len`, `response_len`,
   `truncated`) are the ground truth to diff against ingested events.
