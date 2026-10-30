# NS Delegation Setup Guide

simdns is authoritative for **one** delegated zone (default
`test-telemetry.example.com`). To make real resolvers route queries to it, the
parent zone must delegate that subzone to the host running simdns. Do this only
for a zone you control, in a lab you are authorised to test.

## 1. Pick names and addresses

- Delegated zone: `test-telemetry.example.com`
- simdns host (nameserver): `ns1.test-telemetry.example.com` → `A 198.51.100.10`
  (replace with your lab host's reachable IP)

simdns answers apex `SOA` and `NS` queries authoritatively using the synthetic
nameserver name `ns1.<zone>`, so delegation checkers see a consistent apex.

## 2. Add delegation records to the PARENT zone (`example.com`)

```zone
; in the example.com zone file
test-telemetry      IN  NS   ns1.test-telemetry.example.com.
; glue record (required: the NS is inside the delegated zone)
ns1.test-telemetry  IN  A    198.51.100.10
```

Reload/publish the parent zone. With a hosted DNS provider, add an `NS` record
for `test-telemetry` pointing at `ns1.test-telemetry.example.com` and an `A`
glue record for that nameserver.

## 3. Run simdns on the nameserver host

```bash
# needs root or CAP_NET_BIND_SERVICE to bind :53
sudo ./simdns --config config.example.toml
# or grant the capability once:
sudo setcap 'cap_net_bind_service=+ep' ./simdns && ./simdns -c config.example.toml
```

## 4. Verify

```bash
# directly against the server
dig @198.51.100.10 SOA test-telemetry.example.com +norecurse
dig @198.51.100.10 NS  test-telemetry.example.com +norecurse
dig @198.51.100.10 TXT abc.0.sess01.test-telemetry.example.com +norecurse

# out-of-zone query must be REFUSED
dig @198.51.100.10 A example.org +norecurse        # -> status: REFUSED

# through the public resolution path once delegation has propagated
dig TXT abc.0.sess01.test-telemetry.example.com
```

## 5. Unprivileged local testing (no delegation)

```bash
./simdns --port 5353 --zone test.local
dig @127.0.0.1 -p 5353 TXT nbswy3dp.0.s1.test.local +norecurse
```

## Notes

- Keep the zone dedicated to testing; simdns refuses everything outside it.
- Low answer TTLs (default 60s, and lower in some scenarios) are intentional and
  are themselves a detectable signal.
