"""Offline DNS cache observation replay.

A single cache observation log contains what one recursive cache recorded
over time: positive RRsets, CNAME aliases, name-level NXDOMAIN results and
type-level NODATA results.  This module replays that log with the same
ordering rules a cache would have seen, and answers each logged probe with
the outcome that was actually derivable from the cache at that point in the
log -- not from a later authority snapshot and not from a network lookup.

Ordering model
--------------
Events carry an opaque, unique, positive ``seq``.  The log is replayed in
``seq`` order, never in array order, and same-second events also have an
order.  A fact observed at ``at`` with a remaining ``ttl`` is usable on
``[at, at + ttl)``; at ``event.at >= at + ttl`` it has expired.  A probe
records the answer at the moment its own event is reached;
it never sees a later event, never mutates or refreshes the cache, and a
later event can never rewrite an earlier probe's answer.

Cache update rules (per exact name)
-----------------------------------
* ``nxdomain`` replaces everything cached for that name: any CNAME, any
  RRset, any NODATA.  It applies to the exact name only; descendants keep
  their own facts.
* ``alias`` replaces everything cached for that name with the CNAME.
* ``rrset`` / ``nodata`` replace the name's NXDOMAIN, its CNAME and the
  fact of the same type, while keeping the other address type's fact.
  ``rrset`` replaces the whole RRset (addresses are never appended).

A ttl of zero still performs the replacement so a previous fact cannot
resurface, but it never becomes a readable fact (it is already expired at
its own ``at``).

Probe resolution
----------------
The requested type is followed through the CNAMEs that existed on the
name at probe time, remembering each alias fact's ``seq`` as evidence.
Other name/types are ignored.  The walk stops at the first missing link
(``miss``, only the aliases already taken remain as evidence), at a name
reached twice (``loop``, the alias that caused the repeat is included), or
at a cached terminal result: ``hit`` for an address RRset of the requested
type, ``nxdomain`` or ``nodata``.  A cached NODATA for one type never
affects the other type; a cached NXDOMAIN affects every type at that name.
"""

import ipaddress

from .common import number, require, rows
from .model import dns_name

MAX_EVENTS = 10000
MAX_TTL = 2147483647
QTYPES = ('A', 'AAAA')

_COMMON = 'seq at name kind'
_FIELDS = {
    'rrset': 'qtype ttl addresses',
    'alias': 'ttl target',
    'nxdomain': 'ttl',
    'nodata': 'qtype ttl',
    'probe': 'qtype',
}


def _name(value):
    """Normalize a non-root absolute name to lowercase trailing-dot form.

    This log has no zone origin, so relative names and ``@`` are rejected
    rather than guessed: the input must already be an absolute name.  The
    shared ``dns_name`` rules then lowercase it and reject ``*``, ``%`` and
    any label that is not a plain ASCII DNS label, including the root.
    """
    if not isinstance(value, str) or not value.endswith('.'):
        raise ValueError('absolute DNS name with trailing dot required')
    if value == '.':
        raise ValueError('root name is not allowed')
    return dns_name(value, '.')


def _canonical_address(qtype, value):
    """Canonicalize one address with the shared model's IP rules.

    ``ipaddress`` canonicalizes both families and rejects malformed input;
    an IPv6 scope identifier is rejected explicitly because ``ipaddress``
    accepts it and would otherwise leak ``%zone`` into the cache.
    """
    if not isinstance(value, str) or not value or '%' in value:
        raise ValueError('invalid address')
    address = ipaddress.IPv4Address(value) if qtype == 'A' else ipaddress.IPv6Address(value)
    return str(address)


def _parse(raw):
    if not isinstance(raw, dict):
        raise ValueError('event object required')
    kind = raw.get('kind')
    if not isinstance(kind, str) or kind not in _FIELDS:
        raise ValueError('unsupported event kind')
    require(raw, _COMMON + ' ' + _FIELDS[kind])
    seq = number(raw['seq'], 1, 2 ** 63 - 1)
    at = number(raw['at'], 0, 2 ** 63 - 1)
    name = _name(raw['name'])
    if kind == 'probe':
        qtype = raw['qtype']
        if qtype not in QTYPES:
            raise ValueError('unsupported qtype')
        return {'seq': seq, 'at': at, 'name': name, 'kind': kind, 'qtype': qtype}
    ttl = number(raw['ttl'], 0, MAX_TTL)
    if kind == 'nxdomain':
        return {'seq': seq, 'at': at, 'name': name, 'kind': kind, 'ttl': ttl}
    if kind == 'alias':
        return {'seq': seq, 'at': at, 'name': name, 'kind': kind, 'ttl': ttl, 'target': _name(raw['target'])}
    qtype = raw['qtype']
    if qtype not in QTYPES:
        raise ValueError('unsupported qtype')
    if kind == 'nodata':
        return {'seq': seq, 'at': at, 'name': name, 'kind': kind, 'qtype': qtype, 'ttl': ttl}
    addresses = rows(raw['addresses'])
    if not addresses:
        raise ValueError('addresses must be a non-empty array')
    canonical = sorted({_canonical_address(qtype, address) for address in addresses})
    if len(canonical) != len(addresses):
        raise ValueError('duplicate address in RRset')
    return {'seq': seq, 'at': at, 'name': name, 'kind': kind, 'qtype': qtype, 'ttl': ttl, 'addresses': canonical}


def _parse_log(data):
    require(data, 'events')
    raw_events = rows(data['events'], MAX_EVENTS)
    if not 1 <= len(raw_events) <= MAX_EVENTS:
        raise ValueError('events must contain 1 to 10000 entries')
    events = [_parse(raw) for raw in raw_events]
    seqs = set()
    for event in events:
        if event['seq'] in seqs:
            raise ValueError('duplicate event seq')
        seqs.add(event['seq'])
    if not any(event['kind'] == 'probe' for event in events):
        raise ValueError('at least one probe is required')
    events.sort(key=lambda event: event['seq'])
    previous = None
    for event in events:
        if previous is not None and event['at'] < previous:
            raise ValueError('event times must not retreat in seq order')
        previous = event['at']
    return events


def _live(fact, now):
    """A fact is usable when its own event has happened and it has not expired."""
    return fact is not None and fact['at'] <= now < fact['at'] + fact['ttl']


def _replace(cache, name, fact):
    """Store one fact for ``name`` under the documented replacement rules.

    A zero-ttl fact still clears the facts it replaces; it is simply never
    readable afterwards.
    """
    current = cache.setdefault(name, {})
    kind = fact['kind']
    if kind in ('alias', 'nxdomain'):
        current.clear()
        current[kind] = fact
    else:  # rrset / nodata
        current.pop('nxdomain', None)
        current.pop('alias', None)
        # An address RRset and a NODATA for one type are mutually exclusive;
        # the other address type is untouched.
        current.pop(('nodata' if kind == 'rrset' else 'rrset') + ':' + fact['qtype'], None)
        current[kind + ':' + fact['qtype']] = fact


def _terminal(cache, name, qtype):
    """Live terminal fact at ``name`` for ``qtype``: ('hit'|neg, fact) or None."""
    here = cache.get(name)
    if not here:
        return None
    fact = here.get('nxdomain')
    if fact is not None:
        return ('nxdomain', fact)
    fact = here.get('rrset:' + qtype)
    if fact is not None:
        return ('hit', fact)
    fact = here.get('nodata:' + qtype)
    if fact is not None:
        return ('nodata', fact)
    return None


def _expiry(evidence):
    return min(fact['at'] + fact['ttl'] for _, fact in evidence)


def _walk(cache, name, qtype, now):
    evidence = []
    visited = {name}
    current = name
    while True:
        terminal = _terminal(cache, current, qtype)
        if terminal is not None:
            state, fact = terminal
            if not _live(fact, now):
                return {'status': 'miss', 'terminal_name': current, 'addresses': [],
                        'evidence': [seq for seq, _ in evidence], 'expires_at': None}
            evidence.append((fact['seq'], fact))
            return {'status': state, 'terminal_name': current,
                    'addresses': list(fact['addresses']) if state == 'hit' else [],
                    'evidence': [seq for seq, _ in evidence], 'expires_at': _expiry(evidence)}
        alias = (cache.get(current) or {}).get('alias')
        if not _live(alias, now):
            return {'status': 'miss', 'terminal_name': current, 'addresses': [],
                    'evidence': [seq for seq, _ in evidence], 'expires_at': None}
        evidence.append((alias['seq'], alias))
        target = alias['target']
        if target in visited:
            return {'status': 'loop', 'terminal_name': target, 'addresses': [],
                    'evidence': [seq for seq, _ in evidence], 'expires_at': None}
        visited.add(target)
        current = target


def analyze(data):
    events = _parse_log(data)
    cache = {}
    probes = []
    for event in events:
        if event['kind'] != 'probe':
            _replace(cache, event['name'], event)
            continue
        outcome = _walk(cache, event['name'], event['qtype'], event['at'])
        probes.append({'seq': event['seq'], 'at': event['at'], 'name': event['name'],
                       'qtype': event['qtype'], **outcome})
    return {'probes': probes}
