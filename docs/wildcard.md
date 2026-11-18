# Single-zone wildcard effective-answer audit v1

Offline DNS operators often need to know what an authoritative server would
actually answer for a handful of names in one exported zone — especially
where wildcards are involved — without sending any query. This audit takes
one existing single-zone snapshot plus 1–1000 in-zone query names, and
reports for every name exactly one deterministic outcome and the source of
the answer. It is the contract of `dns_zone_audit.wildcard.analyze` and of
`python -m dns_zone_audit.wildcard_cli`.

## Input contract

Top level is strictly `{"zone": {...}, "queries": [...]}`.

- `zone` is an existing single-zone snapshot (`origin`, `default_ttl`,
  `records`) normalized by the unchanged rules of [contract.md](contract.md):
  ASCII names, relative names, `@`, TTL bounds, IP canonicalization, record
  payloads, duplicate-record rejection, the 8 MB and record-count limits.
- `queries` holds 1–1000 names. Each accepts the existing relative, absolute
  trailing-dot and `@` forms; after normalization names must not repeat, must
  sit at the apex or below it on a label boundary, and must not themselves
  contain a wildcard label.

### Wildcard owners in the shared model

`model.py` now accepts a record owner whose **complete first label** is `*`
(e.g. `*`, `*.branch`, `*` and `*.branch` relative to the apex). That `*`
label survives normalization and the remaining labels are lowercased and
made absolute as usual. No other position is a wildcard: `a.*`, `*a`, `a*b`,
`x.*.y` and `**` are still rejected, and RDATA names (`NS`, `CNAME`, `MX`,
`SOA`) still reject `*` entirely because they are normalized without the
wildcard opt-in. All non-wildcard records and the three existing audits keep
their previous behavior.

## Node existence and empty non-terminals

The zone's node set contains:

- every record owner (a node with an explicit RRset), including non-apex NS
  delegation owners, and
- every strict ancestor of each record owner up to the apex, even when that
  ancestor holds no RRset — these are **empty non-terminals** (ENTs).

The apex always exists. The `*` label of a wildcard owner is never inserted
into another name's ancestor chain: it is stripped left-first, so
`*.branch.example.test.` contributes the ENTs `branch.example.test.` and
`example.test.`, not a node named `*.example.test.` deeper in the chain.

## Evaluation order

Each query name is evaluated once, in this fixed order; the first matching
state wins and later states never override it.

1. **explicit** — the probe has an RRset in the snapshot. Return it, never
   following a CNAME.
2. **delegated** — the probe is a *strict* descendant of a non-apex NS owner.
   `closest_encloser` is the nearest such owner on a label boundary, records
   are empty. With several nested delegation owners the nearest wins. This
   precedes ENTs and wildcards, so a delegated subtree never receives a
   parent-zone wildcard answer. The delegation owner itself is still
   `explicit` and returns its NS RRset.
3. **empty_non_terminal** — the probe is a node derived only from
   descendants. Records are empty and no wildcard is applied.
4. otherwise the **closest encloser** is the longest existing strict
   ancestor (label-boundary matched) of the probe; the apex is always a
   candidate. Only `*.<closest-encloser>` is inspected:
   - an RRset there yields **wildcard**,
   - otherwise **no_match**, with no fallback to a higher ancestor's
     wildcard.

`no_match` keeps the actual closest encloser; `delegated` uses the delegation
owner; a probe with no existing ancestor at all would report a null
closest encloser.

## Output contract

`analyze(data)` returns `{"origin": ..., "answers": [...]}`. `answers` is
sorted by normalized query name; every entry strictly contains `query`,
`state`, `closest_encloser`, `source_owner`, `records`. `state` is one of
`explicit`, `empty_non_terminal`, `wildcard`, `no_match`, `delegated`.

`source_owner` is the true origin owner for `explicit` (the owner itself) and
`wildcard` (the `*.<closest-encloser>` owner); it is null for the other
states. Each record strictly contains `owner`, `source_owner`, `type`, `ttl`,
`data`, sorted by `(type, canonical RDATA)`. An answer's records carry the
materialized effective owner — the query name for `wildcard`, the owner
itself for `explicit` — while `source_owner` traces each record back to the
wildcard RRset it came from. TTL and RDATA are copied unchanged by the
projection.

### Design: materialized owner vs source owner

Two representations were considered. The chosen one materializes every
synthesized record at the query name and separately lists `source_owner`.
Consumers that only want the answer see a normal owner, and auditors can
still recover the wildcard via `source_owner`; the risk is mistaking the
projection for stored data, which `source_owner` makes explicit. The
alternative — keep the wildcard owner and add `synthesized_owner` — would
require every consumer not to treat the wildcard name as a real answer
owner. Either way the effective owner and source owner must both be present
and unambiguous; TTL and RDATA never change with projection.

## Result and CLI

```sh
python -m dns_zone_audit.wildcard_cli --source fixtures/wildcard-input.json --output run/wildcard-report.json
dns-zone-wildcard --source fixtures/wildcard-input.json --output run/wildcard-report.json
```

The report is strictly `{"schema_version": 1, "source_sha256": <sha256 of raw
input bytes>, "result": <interface result>}`, with stdout carrying the same
object. It reuses `common.py`'s strict reading (8 MB cap, duplicate keys and
non-finite numbers rejected) and atomic publication: any input, contract or
write failure exits 2 and leaves a pre-existing report untouched, and input/
output path collisions and symlink outputs are rejected. Results contain no
timestamps, random values or absolute paths; reordered queries or records and
letter-case or relative/absolute name changes do not alter `result`.
Everything runs offline; no DNS query or server change occurs.

## Worked sample

`fixtures/wildcard-input.json` has an apex `*` A wildcard, the derived node
`branch` (from `host.branch`), a nearer `*.branch` A wildcard, an `ops` node
with no wildcard, and a `child` delegation:

| query | state | closest encloser | source owner |
| --- | --- | --- | --- |
| `@` | explicit | apex | apex |
| `anything` | wildcard | apex | `*.example.test.` |
| `branch` | empty_non_terminal | `branch.example.test.` | null |
| `host.branch` | explicit | `host.branch.example.test.` | itself |
| `x.branch` | wildcard | `branch.example.test.` | `*.branch.example.test.` |
| `deep.host.branch` | no_match | `host.branch.example.test.` | null |
| `x.ops` | no_match | `ops.example.test.` | null |
| `child` | explicit | `child.example.test.` | itself |
| `x.child` | delegated | `child.example.test.` | null |

The near-miss cases are the point: `x.branch` must use `*.branch`, never fall
back to the apex `*`; `deep.host.branch` must not use the `*.branch` wildcard
because its own closest encloser is `host.branch`; and `x.child` must be
`delegated` rather than answered by any parent wildcard.
