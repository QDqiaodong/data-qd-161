"""Offline single-zone wildcard effective-answer audit.

For a bounded set of query names inside one exported zone snapshot, decide
for every name whether the authoritative answer is an explicit RRset, is
blocked by a delegation or an empty non-terminal, is synthesized from a
wildcard RRset, or has no usable record.  No network queries are performed:
the result is derived from the snapshot alone.

Wildcard synthesis follows DNS closest-encloser semantics.  The closest
encloser is the longest existing ancestor of the query name; only the
wildcard directly below that node (``*.<closest-encloser>``) may answer.
There is no fallback to a wildcard at a higher ancestor.  Non-apex NS
owners are delegation boundaries: strict descendants of such an owner are
answered as ``delegated`` before any wildcard could apply, while the
delegation owner itself still returns its explicit RRset.
"""
import copy
import json

from .common import require, rows
from .model import analyze as analyze_zone
from .model import dns_name

MAX_QUERIES = 1000


def _canonical(value):
    """Stable text form of normalized RDATA for ordering only."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _strict_ancestors(name, origin):
    """Yield the strict ancestors of ``name`` from longest to apex.

    Labels are stripped from the left, so the ``*`` label of a wildcard
    owner is never inserted into another name's ancestor chain.  ``name``
    must be the apex or sit below it on a label boundary.
    """
    current = name
    while current != origin:
        current = current.split('.', 1)[1]
        yield current


def _label_count(name):
    return name.count('.')


def _materialized(records, owner, source_owner):
    """Copy an RRset to its effective owner while keeping the source owner.

    TTL and RDATA are the normalized wildcard values, unchanged by the
    projection; only the effective ``owner`` differs from ``source_owner``.
    """
    return [{'owner': owner, 'source_owner': source_owner, 'type': record['type'],
             'ttl': record['ttl'], 'data': copy.deepcopy(record['data'])}
            for record in records]


def _record_key(record):
    return (record['type'], _canonical(record['data']))


def _delegation_boundary(name, ns_owners):
    """Longest non-apex NS owner strictly above ``name``, or None.

    A probe strictly below several nested delegation owners is scoped to
    the nearest one on a DNS label boundary.
    """
    matches = [owner for owner in ns_owners if name.endswith('.' + owner)]
    return max(matches, key=_label_count) if matches else None


def analyze(data):
    require(data, 'zone queries')
    audit = analyze_zone(data['zone'])
    origin = audit['origin']
    records = audit['records']

    raw_queries = rows(data['queries'], MAX_QUERIES)
    if not raw_queries:
        raise ValueError('queries must contain 1 to 1000 names')
    probes = []
    seen = set()
    for raw in raw_queries:
        name = dns_name(raw, origin)
        if name != origin and not name.endswith('.' + origin):
            raise ValueError('query name outside zone')
        if name in seen:
            raise ValueError('duplicate query name')
        seen.add(name)
        probes.append(name)

    by_owner = {}
    for record in records:
        by_owner.setdefault(record['owner'], []).append(record)

    # Node existence: every record owner plus every strict ancestor up to
    # the apex.  Ancestors without their own RRset are empty non-terminals.
    nodes = {origin}
    for owner in by_owner:
        nodes.add(owner)
        nodes.update(_strict_ancestors(owner, origin))

    ns_owners = {owner for owner in by_owner
                 if owner != origin and any(record['type'] == 'NS' for record in by_owner[owner])}

    answers = []
    for probe in probes:
        explicit = by_owner.get(probe)
        if explicit:
            state, closest, source = 'explicit', probe, probe
            effective = _materialized(explicit, probe, probe)
        else:
            boundary = _delegation_boundary(probe, ns_owners)
            if boundary is not None:
                state, closest, source, effective = 'delegated', boundary, None, []
            elif probe in nodes:
                state, closest, source, effective = 'empty_non_terminal', probe, None, []
            else:
                # Closest encloser is the longest existing strict ancestor;
                # the apex is always a node, so a match normally exists.  A
                # name with no existing ancestor would keep a null encloser.
                closest = next((node for node in _strict_ancestors(probe, origin) if node in nodes), None)
                matched = by_owner.get('*.' + closest) if closest is not None else None
                if matched:
                    state, source = 'wildcard', '*.' + closest
                    effective = _materialized(matched, probe, source)
                else:
                    state, source, effective = 'no_match', None, []
        effective.sort(key=_record_key)
        answers.append({'query': probe, 'state': state, 'closest_encloser': closest,
                        'source_owner': source, 'records': effective})

    answers.sort(key=lambda answer: answer['query'])
    return {'origin': origin, 'answers': answers}
