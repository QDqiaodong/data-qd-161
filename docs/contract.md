# Authoritative DNS zone audit v1

Offline DNS operators provide origin, default_ttl and up to 10,000 structured records. Names accept ASCII DNS labels, relative names, absolute trailing-dot names and @ for the zone apex; names canonicalize to lowercase absolute form. A record owner may additionally begin with a complete `*` label (`*`, `*.branch`); any other use of `*` and any `*` in RDATA names is rejected. Supported types are SOA, NS, A, AAAA, CNAME, MX and one-string TXT. TTL is null to use default_ttl or an integer from 0 through 2^31-1. SOA serial is 32-bit unsigned; other timers are bounded nonnegative integers.

The audit reports, rather than silently repairs, apex SOA count, missing apex NS, CNAME coexistence, MX-to-CNAME targets, and missing in-zone nameserver glue for child delegations. Input syntax, duplicate records, unsupported types and invalid IP addresses are rejected. Data is a declarative zone snapshot; no DNS queries or server changes occur.

The synthetic fixture has an apex SOA/NS and a child delegation. A missing glue A record is reported as a finding while the CLI succeeds. This is not a complete RFC zone-file parser, DNSSEC validator, or live resolver.

A separate multi-zone audit answers a different question: given several same-instant zone snapshots and the directly reachable root zones, can each zone's first usable authoritative endpoint be obtained from the roots, and which datum proves it. Its input/output contract, authority and rounds model, and design tradeoffs live in [bootstrap.md](bootstrap.md); it reuses this document's name, TTL, IP and record rules per zone and never lets the local findings above reject input or decide reachability.

A third audit compares a current and a candidate snapshot of one origin: it reuses the same per-zone normalization, reports normalized resource-record differences by RDATA identity plus TTL, and combines them with an RFC 1982 SOA serial comparison into a publish decision. See [change.md](change.md).

A fourth audit answers, for 1–1000 query names in one zone, whether the effective answer is an explicit RRset, blocked by a delegation or empty non-terminal, synthesized by the nearest wildcard, or absent. It shares this document's name/record rules; a record owner may now use a complete first label `*`, which no other audit interprets. See [wildcard.md](wildcard.md).

Separately, an importer compiles a locally maintained text bundle — one entry fragment plus the raw text fragments it references, written in a restricted internal master-file-like dialect — into this document's single-zone snapshot, keeping the full source position (fragment, line, include chain) of every record so the existing audit can consume the snapshot while reviewers trace which include produced which record. It reuses this document's normalization and duplicate-record identity unchanged and never alters the audits above. See [zone-import.md](zone-import.md).

A final, independent audit replays one cache's observation log: it applies positive RRsets, CNAMEs, name-level NXDOMAIN and type-level NODATA in `seq` order with the recorded remaining TTLs, and reports for each logged probe the result the cache could produce at that position plus the observation sequence numbers used as evidence. It performs no lookup and reads no clock; its log model and output live in [cache-replay.md](cache-replay.md).
