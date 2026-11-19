# Offline DNS cache observation replay v1

An operator usually has one cache's observation log, not an authoritative
zone snapshot. This audit replays that log and answers each logged probe
with exactly the result the cache could have produced **at that probe's
position in the log**, plus the observation `seq` numbers that justify it.
It performs no DNS lookup, reads no system clock, and models no resolver
beyond the cache facts written into the log. It is the contract of
`dns_zone_audit.cache_replay.analyze` and of
`python -m dns_zone_audit.cache_replay_cli` / `dns-zone-cache-replay`.

## Input contract

Top level is strictly `{"events": [...]}` with 1–10000 events and at least
one `probe`. Every event has exactly `seq`, `at`, `name`, `kind` plus the
fields of its kind; any other or missing field is rejected.

| `kind` | extra fields |
| --- | --- |
| `rrset` | `qtype`, `ttl`, `addresses` (non-empty array of matching-family IP strings) |
| `alias` | `ttl`, `target` (absolute CNAME target) |
| `nxdomain` | `ttl` |
| `nodata` | `qtype`, `ttl` |
| `probe` | `qtype` |

- `seq` is a unique positive integer; gaps are fine. Array order carries no
  business meaning.
- `at` is a nonnegative integer second. After sorting by `seq`, `at` must
  never retreat; equal seconds are allowed and are ordered by `seq`.
- `qtype` is only `A` or `AAAA`.
- `name` and `target` use the shared repository ASCII label rules
  ([contract.md](contract.md)) but must be absolute non-root names with a
  trailing dot. Relative names, `@`, the root and wildcards are rejected.
- `ttl` is the recorded **remaining** seconds, `0..2^31-1`. No integer
  field accepts a JSON boolean.
- Addresses are canonicalized with the shared IP rules; an IPv6 scope
  identifier (`%zone`) is rejected, and an RRset may not repeat an address
  after canonicalization.

## Fact lifetime and supersession

The log is replayed in `seq` order. A fact observed at `at` with `ttl` is
usable on `[at, at + ttl)`; at `at + ttl` it has expired. A ttl of `0`
performs its replacement but is never readable.

Writes coordinate per exact name:

- `nxdomain` replaces every fact at that name (CNAME, RRset, NODATA) and
  affects only the exact name, never descendants.
- `alias` replaces every fact at that name with the CNAME.
- `rrset` / `nodata` replace that name's NXDOMAIN, CNAME and the fact of
  the same type, while keeping the other address type. An `rrset` replaces
  the whole RRset; addresses are never appended.

A superseded fact never comes back, even if its own TTL has not elapsed.

## Probe resolution and evidence

A probe follows the CNAMEs that were live on its requested type at probe
time, then reports one of:

- `hit` — an address RRset of the requested type at the terminal;
- `nxdomain` / `nodata` — the terminal cached negative result;
- `miss` — a link or terminal fact is absent or expired;
- `loop` — a name is reached twice.

`evidence` is the `seq` of each alias actually traversed plus, for a
terminal positive or negative result, the terminal fact's `seq`. A `hit`'s
`addresses` are the terminal RRset's canonical strings, sorted; every other
status has an empty array. `terminal_name` is the name where the walk
stopped; on a loop it is the first name reached a second time.
`expires_at` is `min(at + ttl)` over the evidence for `hit`, `nxdomain` and
`nodata` (an upper bound of the known facts' TTLs, ignoring future
supersession), and `null` for `miss` and `loop`.

Probes never write to the cache, never refresh a TTL, and never write a
terminal negative result back onto an alias.

## How same-second results stay consistent with evidence

Both the cache and each probe answer are derived from one ordered replay,
so a probe's evidence is by construction the set of facts it used, and the
cache state it saw is exactly the cache state produced by all earlier
events:

1. All events are validated and then sorted by `(seq)` — never by array
   index. A probe at `seq` therefore sees every event with a smaller `seq`
   and no event with a larger `seq`, including within one second.
2. The replay applies events one at a time: an observation mutates the
   cache before the next event is examined; a probe is answered from the
   cache as it stands at that instant and does not mutate it.
3. Expiry is a pure function of the fact's own `at`/`ttl` and the probe's
   `at`, so a later observation cannot change an earlier probe's answer,
   and a same-second probe before an observation can never read it while a
   probe after it always can.
4. `evidence` and `expires_at` are computed from the very fact objects the
   walk visited, so the reported `seq`s and TTL bound always match the
   terminal decision that was made.

A short-lived NXDOMAIN is the sharp example: at its `seq` it hides an
older positive RRset at the same name; once `at + ttl` is reached the
NXDOMAIN is gone and the older positive result must **not** reappear —
the probe reports `miss`, not the stale address.

## Result and CLI

```sh
python -m dns_zone_audit.cache_replay_cli --source fixtures/cache-replay-input.json --output run/cache-replay-report.json
dns-zone-cache-replay --source fixtures/cache-replay-input.json --output run/cache-replay-report.json
```

The report is strictly `{"schema_version": 1, "source_sha256": <sha256 of
raw input bytes>, "result": {"probes": [...]}}`, with stdout carrying the
same object. `probes` is ordered by `seq`; each entry has `seq`, `at`,
`name`, `qtype`, `status`, `terminal_name`, `addresses`, `evidence`,
`expires_at`. It reuses `common.py`'s strict reading (8 MB cap, duplicate
keys and non-finite numbers rejected) and atomic publication: any input,
contract or write failure exits 2 and leaves a pre-existing report
untouched; input/output path collisions and symlink outputs are rejected.
Everything runs offline; no DNS query, system clock read or server change
occurs.

## Worked sample

`fixtures/cache-replay-input.json` encodes all three acceptance examples
(names `a`/`b`/`c` are `a.example.test.` etc.):

| probe seq | at | query | status | terminal | evidence | expires_at |
| --- | --- | --- | --- | --- | --- | --- |
| 13 | 1 | a/A | hit | b | `[12, 10]` | 60 |
| 15 | 2 | a/A | nxdomain | b | `[12, 14]` | 5 |
| 16 | 5 | a/AAAA | miss | b | `[12]` | null |
| 18 | 5 | a/A | miss | c | `[12, 17]` | null |
| 20 | 5 | a/A | hit | c | `[12, 17, 19]` | 15 |

Probe 15 shows b's short NXDOMAIN (ttl 3 at t=2, expiring at t=5)
overriding the still-fresh A/AAAA; probe 16 at t=5 shows that after the
negative expires the old AAAA does **not** reappear. Probes 18 and 20 are
in the same second: before c's A is written the alias chain still ends in
`miss`, and after it the same chain `hit`s with the new address.
