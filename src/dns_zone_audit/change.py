"""Offline DNS zone snapshot change audit.

Compare two snapshots of the same origin: match resource records by their
normalized ``(owner, type, RDATA)`` identity, report TTL and RDATA changes,
and combine that difference with an RFC 1982 serial comparison into a
deterministic publish decision. No network queries or server changes occur.
"""
import json

from .common import require
from .model import analyze as analyze_zone

_SERIAL_SPACE = 2 ** 32
_HALF_SPACE = 2 ** 31


def _canonical(value):
    """Stable text form of normalized RDATA for identity and ordering."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _snapshot(value):
    audit = analyze_zone(value)
    origin = audit['origin']
    apex_soa = [record for record in audit['records']
                if record['owner'] == origin and record['type'] == 'SOA']
    if len(apex_soa) != 1:
        raise ValueError('each snapshot must contain exactly one apex SOA')
    records = {}
    for record in audit['records']:
        identity = (record['owner'], record['type'], _canonical(record['data']))
        records[identity] = record
    return origin, records, apex_soa[0]['data']['serial']


def _serial_state(current, candidate):
    delta = (candidate - current) % _SERIAL_SPACE
    if delta == 0:
        relation = 'same'
    elif delta < _HALF_SPACE:
        relation = 'newer'
    elif delta == _HALF_SPACE:
        relation = 'ambiguous'
    else:
        relation = 'older'
    return delta, relation


def _side(record):
    if record is None:
        return None
    return {'ttl': record['ttl'], 'data': record['data']}


def _changes(current, candidate):
    changes = []
    for identity in set(current) | set(candidate):
        before = current.get(identity)
        after = candidate.get(identity)
        if before is not None and after is not None:
            change = 'unchanged' if before['ttl'] == after['ttl'] else 'ttl_changed'
        elif before is not None:
            change = 'removed'
        else:
            change = 'added'
        data = (before or after)['data']
        owner, kind, rdata = identity
        changes.append((owner, kind, rdata, change, {
            'change': change,
            'identity': {'owner': owner, 'type': kind, 'data': data},
            'before': _side(before),
            'after': _side(after),
        }))
    changes.sort(key=lambda item: item[:4])
    return [item[4] for item in changes]


def analyze(data):
    require(data, 'current candidate')
    current_origin, current_records, current_serial = _snapshot(data['current'])
    candidate_origin, candidate_records, candidate_serial = _snapshot(data['candidate'])
    if current_origin != candidate_origin:
        raise ValueError('snapshots must share the same origin')
    delta, relation = _serial_state(current_serial, candidate_serial)
    changes = _changes(current_records, candidate_records)
    summary = {name: 0 for name in ('added', 'removed', 'ttl_changed', 'unchanged')}
    for change in changes:
        summary[change['change']] += 1
    return {
        'origin': current_origin,
        'serial': {
            'current': current_serial,
            'candidate': candidate_serial,
            'delta': delta,
            'relation': relation,
        },
        'can_publish': relation == 'newer',
        'changes': changes,
        'summary': summary,
    }
