# simdns Wire-Format Specification

This document defines the on-the-wire contract between an emulated **client**
(out of scope for this repo) and the simdns server, so client tooling can be
built against a stable format. simdns is a *detection-engineering harness*: the
format is deliberately simple and detectable, with no evasion.

All names are case-insensitive per DNS; simdns lower-cases before processing.

---

## 1. Inbound channel (query-based)

Data is carried in the subdomain labels of the QNAME, beneath the configured
zone apex `<zone>`:

```
<payload-1>.<payload-2>. ... .<payload-N>.<seq>.<session-id>.<zone>
                                   |            |
                                   |            +-- rightmost label below apex
                                   +-- immediately left of <session-id>
```

Parsing rules (as implemented in `src/handler.rs::parse_inbound`):

1. **session-id** — the label immediately below the zone apex (rightmost
   sub-zone label). Present whenever at least one label exists below the apex.
   Used to correlate chunked queries into one logical transfer.
2. **seq** — the label immediately to the left of `session-id`, parsed as a
   decimal `u32`. If that label is **not** a valid non-negative integer, it is
   treated as payload and `seq` is considered absent. Monotonic per session is
   recommended; the server records the max seq seen (gap/reassembly telemetry).
3. **payload** — every label to the left of `seq` (or to the left of
   `session-id` if no seq is present), **concatenated left-to-right into a
   single string**, then decoded once using the configured encoding
   (`base32` | `hex` | `base64url`). Undecodable input is logged with
   `payload_len = 0` rather than rejected.

### Constraints (RFC 1035)

- Each label MUST be ≤ **63** bytes.
- The total FQDN MUST be ≤ **253** bytes (255 on the wire).
- Clients therefore chunk the encoded stream across multiple labels and across
  multiple queries (using `seq` for ordering).

### Encoding guidance

| Encoding    | Alphabet                         | Relative entropy | Use |
|-------------|----------------------------------|------------------|-----|
| `hex`       | `0-9a-f`                         | low              | entropy-threshold tuning (below-threshold) |
| `base32`    | `A-Z2-7` (case-insensitive)      | medium (default) | realistic DNS-safe tunneling |
| `base64url` | `A-Za-z0-9-_`                    | high             | entropy-threshold tuning (above-threshold) |

### Example

Zone `test-telemetry.example.com`, encoding `base32`, session `sess01`, seq `5`,
payload bytes `hello` (base32 `NBSWY3DP`):

```
nbswy3dp.5.sess01.test-telemetry.example.com
```

A multi-label chunk `nbswy3dp` split as `nbsw.y3dp`:

```
nbsw.y3dp.5.sess01.test-telemetry.example.com
```
(labels concatenated → `nbswy3dp` → decoded → `hello`.)

---

## 2. Outbound channel (response-based)

For an in-zone query that is dispositioned to **answer**, the server returns one
record in the answer section. The type is chosen as follows:

- If `profile.honor_qtype = true` (default) **and** the QTYPE is one of
  `TXT | A | AAAA | CNAME | NULL`, the answer uses that type.
- Otherwise the type is drawn from the weighted `profile.record_mix`. With
  `honor_qtype = false` this happens for *every* answer, regardless of QTYPE —
  deliberately producing a QTYPE/answer-type mismatch anomaly when they differ.

| Answer type | Payload |
|-------------|---------|
| `TXT`   | `channel.txt_payload_bytes` of random URL-safe ASCII, split into ≤255-byte character-strings |
| `A`     | a random address from `channel.a_pool` |
| `AAAA`  | a random address from `channel.aaaa_pool` |
| `CNAME` | `channel.cname_target` |
| `NULL`  | `channel.null_payload_bytes` of random bytes |

All answers use `channel.answer_ttl_secs` as the record TTL.

---

## 3. Control and error responses

| Condition | Response |
|-----------|----------|
| QNAME outside the zone | `REFUSED`, non-authoritative |
| Apex `SOA` query | authoritative `SOA` (mname `ns1.<zone>`) |
| Apex `NS` query | authoritative `NS` → `ns1.<zone>` |
| Disposition roll < `nxdomain_rate` | `NXDOMAIN` with `SOA` in the authority section |
| Disposition roll < `nxdomain_rate + servfail_rate` | `SERVFAIL` |
| Unparseable packet / non-QUERY opcode / ≠1 question | `FORMERR` (txn id salvaged from the first 2 bytes when possible), never a panic |
| UDP answer larger than the client's buffer (EDNS0 `max_payload`, else 512) | `TC=1`, record sections dropped, prompting TCP retry |

## 4. Transport

- **UDP/53** and **TCP/53** both enabled by default.
- **TCP framing**: RFC 1035 §4.2.2 — a 2-byte big-endian length prefix precedes
  each DNS message. A single TCP connection may carry multiple sequential
  query/response pairs. Messages with a prefix of `0` or greater than
  `server.tcp_max_message_bytes` cause the connection to be closed.

## 5. Session semantics

A session is created on first sight of its id and updated on each subsequent
query. Per-session the server tracks: query count, accumulated decoded payload
bytes, and max seq. Sessions idle longer than `session.ttl_secs` are evicted;
the total is hard-capped at `session.max_sessions` (further new sessions are
rejected and counted in `sessions_rejected`, never growing memory unbounded).
