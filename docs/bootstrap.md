# Multi-zone bootstrap reachability audit v1

Offline DNS operators hold several zone snapshots exported at the same instant
and need to know, without any network query, whether the first usable
authoritative endpoint of every zone can be obtained starting from a set of
already reachable root zones — and which single datum supports each verdict.
This document is the business contract of `dns_zone_audit.bootstrap.analyze`
and of `python -m dns_zone_audit.bootstrap_cli`. The single-zone audit of
[contract.md](contract.md) stays unchanged; its `issues` are local findings
that neither reject bootstrap input nor decide bootstrap results.

## Input contract

Top level is strictly `{"zones": [...], "roots": [...]}`.

- `zones`: 1–128 objects, each strictly `origin`/`default_ttl`/`records` and
  normalized by the unchanged single-zone rules (ASCII names, relative names,
  `@`, TTL bounds, IP canonicalization, record payloads, duplicate-record
  rejection). The whole file holds at most 10,000 records and 8 MB.
- `roots`: nonempty array of absolute domain names with a trailing dot.
- After normalization, zone origins must not repeat and root names must not
  repeat. No record types beyond the existing set are introduced.

Structural contract, checked before any reachability computation; violations
are contract errors (CLI exit 2, previous report preserved):

1. `roots` must list exactly the origins that have no strict ancestor zone in
   the set. Ancestors are matched on DNS label boundaries, never by string
   `endswith` coincidence.
2. Every non-root zone's parent is the longest strict ancestor present in the
   set, and the parent must hold a *valid delegation* at the child origin: a
   non-apex NS owner not occluded by a shallower non-apex NS owner. All NS
   records at one owner form one delegation. A valid delegation without a
   child snapshot is legal input, not an error.

## Authority model

- Authority is cut by label suffix and the shallowest non-apex NS. Records at
  or below a valid delegation are not authoritative data of the parent; an NS
  owner below a shallower valid delegation opens no delegation of its own.
- The authoritative zone of an external NS host is found by descending from
  the matching root zone along the valid delegations containing the host. A
  delegation without a snapshot blocks the descent: the source is unknown and
  no fallback upward or sideways is allowed. A host matching no root zone is
  likewise unknown. Deeper snapshots only count when the whole parent chain
  above them satisfies the delegation contract.
- Address supply: only a reachable authoritative zone provides direct A/AAAA
  for external NS targets. Glue stays scoped to its own delegation — it serves
  only NS targets listed by that delegation and inside the delegated subtree,
  and never enters a global address pool. CNAME is never followed; a target
  with only a CNAME has no direct address, and a target with both CNAME and
  A/AAAA is decided by the direct addresses alone.

For a delegation from parent `p` to child `z`, the candidate NS set is exactly
`p`'s NS records at `z.origin`:

- Target at or below `z.origin` → channel `glue`: the only supply is `p`'s
  direct A/AAAA at the same name. The child's own addresses cannot bootstrap
  the child, and glue of other delegations cannot be borrowed.
- Target outside `z.origin` → channel `authority`: the only supply is the
  direct A/AAAA at the same name in the located authoritative zone `h`, and
  `h` must be reachable. A same-name non-authoritative copy in `p` does not
  count. Address values carry no extra reachability or subnet judgment; one A
  or one AAAA suffices.

## Rounds and minimal closure

Root zones hold at round 0. A non-root zone holds only when its parent is
reachable **and** at least one candidate yields a usable address — both
conditions, never the snapshot's own addresses alone. Zone reachability
enables that zone's authoritative addresses, which in turn enable dependent
zones; the result is the minimal closure supported by the roots alone, so two
mutually dependent zones cannot certify each other.

Observable semantics are synchronous rounds: round k+1 may use only zones
established by the end of round k. A glue proof needs the parent; an authority
proof needs the parent and the address's zone. A candidate proof's round is
`1 + max(rounds of required zones)`; a zone's `round` is the minimum over its
rooted proofs, or `null` when none exists. The definition is not tied to an
algorithm: depth-first search must not permanently fail on a cycle, and a
cycle of existing records must not pass by itself.

## Output contract

`analyze(data)` returns `{"zones": [...], "all_reachable": bool}`. Zones are
sorted by normalized origin; each entry strictly contains `origin`, `parent`
(null for roots), `reachable`, `round`, `witness`, `candidates`. Roots have
`witness: null` and `candidates: []`.

Non-root `candidates` are sorted by normalized NS name, one entry per distinct
NS, each strictly containing:

- `ns`, `channel` (`glue`/`authority`), `address_zone` (parent for glue,
  located authoritative zone for authority, null when unknown),
- `addresses`: direct IPs of the source zone for this name, string-sorted,
  never input-ordered; empty when there is no legal source. The list may name
  addresses that belong to the source but are not yet obtainable — presence
  alone never makes a candidate ready.
- `ready`, `waiting_on`, `reason`: `authority_unknown` when the source is
  unknown, `address_missing` when the source is known but has no qualified
  direct address (both with `waiting_on: []` and `ready: false`); otherwise
  `waiting_on` is the deduplicated, origin-sorted list of required zones not
  reachable in the final closure (glue: the parent; authority: parent and
  address zone), and the candidate is `ready` exactly when `waiting_on` is
  empty, with `reason` `ready` or `waiting` accordingly.

An unreachable zone has `witness: null`. A reachable non-root zone's witness
contains `ns`, `channel`, `address_zone`, `address`: among the candidates
achieving the zone's minimal round, the smallest `(ns, channel, address_zone,
address)` string tuple, so the witness and the round always come from the same
derivation — a lexicographically smaller NS that only proves later is never
preferred. `all_reachable` only states whether every given zone is reachable.

The CLI report is `{"schema_version": 1, "source_sha256": <sha256 of raw input
bytes>, "result": <interface result>}`; stdout carries the same JSON object.
Strict JSON reading (8 MB cap, duplicate keys and non-finite numbers rejected)
and atomic report publication are inherited from the original command, as are
exit code 2 with the previous report preserved on any input or contract
failure. Reordered arrays or records, letter case, and equivalent IPv6
spellings do not change `result`; `source_sha256` faithfully tracks raw bytes.
Reports contain no timestamps or random values, and a legal but
unbootstrappable input still exits 0 with a report.

## Design: explicit dependency rules vs on-demand authority evaluation

Two organizations were considered.

**On-demand authority evaluation** answers "is zone z reachable, and at which
round?" by memoized recursion: locating an NS target's authoritative zone,
evaluating that zone, and so on, descending from the roots. It computes only
what is queried, but the three obligations of this audit become distributed
and fragile: source scoping must be threaded through every recursive step so
that glue never leaks into a global pool; cycles must be treated as
"not yet proven" rather than failure or success, which forces iterative
deepening or an explicit least-fixed-point driver anyway; and round minimality
requires the recursion to enumerate alternative proofs in round order.

**Explicit dependency rules** (chosen) first compiles every zone's candidate
proofs into static records — `(ns, channel, address_zone, addresses,
required_zones)` — and then settles zones in increasing proof-round order:
roots at round 0, and repeatedly the pending zone whose best candidate round
`1 + max(required rounds)` is smallest, until nothing more can be proven. The
obligations become local and auditable:

- *Source scoping* is decided once per candidate, before the closure: glue
  reads only the parent at the exact owner, authority reads only the located
  zone at the exact owner, and no address ever leaves its zone of scope.
- *Waiting dependencies* are read off the final closure: `waiting_on` is the
  set difference between a candidate's required zones and the reached set, so
  the report explains precisely which regions each candidate still waits on.
- *Round minimality* holds by a Dijkstra-style argument: zones are settled in
  nondecreasing round order, and any proof discovered later would depend on a
  zone settled at round ≥ k and therefore cost ≥ k+1, so a settled round is
  final. Cycles simply never become provable from the roots, and mutually
  dependent zones are handled without any special case.

The price is computing candidates for zones that may stay unreachable, which
is bounded by 128 zones and the delegation fan-out and is irrelevant next to
the input parsing cost.

## Worked sample

`fixtures/bootstrap-input.json` models the acceptance cycle: root
`example.test.`, siblings `a.example.test.` (NS `ns.b.example.test.` and
`boot.a.example.test.`) and `b.example.test.` (NS `ns.a.example.test.`). Each
sibling keeps its own nameserver addresses in its own snapshot, which cannot
bootstrap anything. With no address for these hosts in the parent, both
siblings are unreachable: `boot.a.example.test.` is `address_missing`, and the
cross-zone candidates wait on the unreachable sibling.

Adding one glue record `boot.a.example.test. A 192.0.2.10` to the parent
breaks the cycle in dependency order (abridged from the real report):

```json
{"origin": "a.example.test.", "reachable": true, "round": 1,
 "witness": {"ns": "boot.a.example.test.", "channel": "glue",
             "address_zone": "example.test.", "address": "192.0.2.10"}}
{"origin": "b.example.test.", "reachable": true, "round": 2,
 "witness": {"ns": "ns.a.example.test.", "channel": "authority",
             "address_zone": "a.example.test.", "address": "192.0.2.1"}}
```

Removing the glue, or replacing it with a CNAME-only record, restores the
initial all-unreachable state; a same-name address kept only in the child's
own snapshot, an out-of-scope parent copy, or an occluded record below a
missing snapshot never produces this change. The automated counterexamples in
`tests/test_bootstrap.py` pin each of these cases.
