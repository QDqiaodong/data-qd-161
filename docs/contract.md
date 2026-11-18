# Authoritative DNS zone audit v1

Offline DNS operators provide origin, default_ttl and up to 10,000 structured records. Names accept ASCII DNS labels, relative names, absolute trailing-dot names and @ for the zone apex; names canonicalize to lowercase absolute form. Supported types are SOA, NS, A, AAAA, CNAME, MX and one-string TXT. TTL is null to use default_ttl or an integer from 0 through 2^31-1. SOA serial is 32-bit unsigned; other timers are bounded nonnegative integers.

The audit reports, rather than silently repairs, apex SOA count, missing apex NS, CNAME coexistence, MX-to-CNAME targets, and missing in-zone nameserver glue for child delegations. Input syntax, duplicate records, unsupported types and invalid IP addresses are rejected. Data is a declarative zone snapshot; no DNS queries or server changes occur.

The synthetic fixture has an apex SOA/NS and a child delegation. A missing glue A record is reported as a finding while the CLI succeeds. This is not a complete RFC zone-file parser, DNSSEC validator, or live resolver.
