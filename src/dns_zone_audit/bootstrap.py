"""Multi-zone offline bootstrap reachability audit.

Given same-instant snapshots of several authoritative zones plus the root
zones that are known to be directly reachable, decide for every zone whether
its first usable authoritative endpoint can be obtained starting from the
root zones only. No network queries are performed; the result is the minimal
closure supported exclusively by the roots, observed in synchronous rounds.
"""
from .common import require, ident, rows
from .model import analyze as analyze_zone
from .model import dns_name

MAX_ZONES = 128
MAX_RECORDS = 10000


def _absolute_name(value):
    ident(value)
    if not value.endswith('.'):
        raise ValueError('expected absolute domain name with trailing dot')
    return dns_name(value, '.')


def _below(name, ancestor):
    """True when name sits strictly below ancestor on a DNS label boundary."""
    return name.endswith('.' + ancestor)


def _at_or_below(name, ancestor):
    return name == ancestor or _below(name, ancestor)


class _Zone:
    """Normalized per-zone view: direct addresses and valid delegations."""

    def __init__(self, audit):
        self.origin = audit['origin']
        addresses = {}
        ns_targets = {}
        for record in audit['records']:
            owner = record['owner']
            kind = record['type']
            if kind in ('A', 'AAAA'):
                addresses.setdefault(owner, set()).add(record['data'])
            elif kind == 'NS':
                ns_targets.setdefault(owner, set()).add(record['data'])
        # Direct A/AAAA at an owner, string-sorted; CNAME never counts.
        self.addresses = {owner: sorted(values) for owner, values in addresses.items()}
        ns_targets = {owner: sorted(values) for owner, values in ns_targets.items()}
        # A valid delegation is a non-apex NS owner not occluded by a
        # shallower non-apex NS owner; one owner forms one delegation.
        self.delegations = {}
        for owner, targets in ns_targets.items():
            if owner == self.origin:
                continue
            if any(_below(owner, other) for other in ns_targets if other != owner and other != self.origin):
                continue
            self.delegations[owner] = targets


def analyze(data):
    require(data, 'zones roots')
    raw_zones = rows(data['zones'], MAX_ZONES)
    if not raw_zones:
        raise ValueError('zones must contain 1 to 128 zone objects')
    raw_roots = data['roots']
    if not isinstance(raw_roots, list) or not raw_roots or len(raw_roots) > MAX_ZONES:
        raise ValueError('roots must be a nonempty array of at most 128 names')
    roots = [_absolute_name(value) for value in raw_roots]
    if len(set(roots)) != len(roots):
        raise ValueError('duplicate root name')

    zones = []
    total_records = 0
    for raw in raw_zones:
        audit = analyze_zone(raw)
        total_records += audit['record_count']
        if total_records > MAX_RECORDS:
            raise ValueError('total record budget exceeded')
        zones.append(_Zone(audit))
    by_origin = {}
    for zone in zones:
        if zone.origin in by_origin:
            raise ValueError('duplicate zone origin')
        by_origin[zone.origin] = zone

    # Parent is the longest strict ancestor present in the set, matched on
    # label boundaries; zones without one are the candidate roots.
    parent = {}
    for zone in zones:
        ancestors = [origin for origin in by_origin if _below(zone.origin, origin)]
        parent[zone.origin] = max(ancestors, key=lambda origin: origin.count('.')) if ancestors else None
    root_origins = sorted(origin for origin, p in parent.items() if p is None)
    if sorted(roots) != root_origins:
        raise ValueError('roots must list exactly the zone origins without a strict ancestor zone')
    for zone in zones:
        p = parent[zone.origin]
        if p is not None and zone.origin not in by_origin[p].delegations:
            raise ValueError('parent zone ' + p + ' has no valid delegation at ' + zone.origin)

    def locate(name):
        """Authoritative zone origin for name, or None when unknown.

        Descend from the matching root along valid delegations containing the
        name; a delegation without a snapshot blocks the descent, and no
        fallback to a shallower zone is allowed.
        """
        current = None
        for origin in root_origins:
            if _at_or_below(name, origin):
                current = origin
                break
        if current is None:
            return None
        while True:
            deeper = None
            for delegation in by_origin[current].delegations:
                if _at_or_below(name, delegation):
                    deeper = delegation
                    break
            if deeper is None:
                return current
            if deeper not in by_origin:
                return None
            current = deeper

    # Candidate proofs per non-root zone, taken only from the parent's NS
    # records at the child origin. Glue stays scoped to its delegation;
    # external targets resolve to exactly one authoritative source zone.
    candidates = {}
    for zone in zones:
        p = parent[zone.origin]
        if p is None:
            candidates[zone.origin] = []
            continue
        entries = []
        for target in by_origin[p].delegations[zone.origin]:
            if _at_or_below(target, zone.origin):
                entries.append({'ns': target, 'channel': 'glue', 'address_zone': p,
                                'addresses': by_origin[p].addresses.get(target, []), 'required': [p]})
            else:
                source = locate(target)
                if source is None:
                    entries.append({'ns': target, 'channel': 'authority', 'address_zone': None,
                                    'addresses': [], 'required': None})
                else:
                    entries.append({'ns': target, 'channel': 'authority', 'address_zone': source,
                                    'addresses': by_origin[source].addresses.get(target, []),
                                    'required': sorted({p, source})})
        candidates[zone.origin] = entries

    # Minimal rooted closure in synchronous rounds. Zones are settled in
    # increasing proof-round order; a settled round is final because any
    # later-settled dependency has an equal or higher round and could only
    # yield strictly later proofs.
    rounds = {origin: 0 for origin in root_origins}
    pending = set(by_origin) - set(root_origins)
    while True:
        best_origin = None
        best_round = None
        for origin in sorted(pending):
            zone_round = None
            for entry in candidates[origin]:
                if entry['address_zone'] is None or not entry['addresses']:
                    continue
                if not all(required in rounds for required in entry['required']):
                    continue
                proof_round = 1 + max(rounds[required] for required in entry['required'])
                if zone_round is None or proof_round < zone_round:
                    zone_round = proof_round
            if zone_round is not None and (best_round is None or zone_round < best_round):
                best_origin = origin
                best_round = zone_round
        if best_origin is None:
            break
        rounds[best_origin] = best_round
        pending.discard(best_origin)

    result_zones = []
    for origin in sorted(by_origin):
        p = parent[origin]
        reachable = origin in rounds
        witness = None
        entries_out = []
        if p is not None:
            for entry in candidates[origin]:
                if entry['address_zone'] is None:
                    reason, waiting_on, ready = 'authority_unknown', [], False
                elif not entry['addresses']:
                    reason, waiting_on, ready = 'address_missing', [], False
                else:
                    waiting_on = [required for required in entry['required'] if required not in rounds]
                    ready = not waiting_on
                    reason = 'ready' if ready else 'waiting'
                entries_out.append({'ns': entry['ns'], 'channel': entry['channel'],
                                    'address_zone': entry['address_zone'], 'addresses': entry['addresses'],
                                    'ready': ready, 'waiting_on': waiting_on, 'reason': reason})
            if reachable:
                best_key = None
                for entry in candidates[origin]:
                    if entry['address_zone'] is None or not entry['addresses']:
                        continue
                    if not all(required in rounds for required in entry['required']):
                        continue
                    proof_round = 1 + max(rounds[required] for required in entry['required'])
                    if proof_round != rounds[origin]:
                        continue
                    for address in entry['addresses']:
                        key = (entry['ns'], entry['channel'], entry['address_zone'], address)
                        if best_key is None or key < best_key:
                            best_key = key
                witness = {'ns': best_key[0], 'channel': best_key[1],
                           'address_zone': best_key[2], 'address': best_key[3]}
        result_zones.append({'origin': origin, 'parent': p, 'reachable': reachable,
                             'round': rounds.get(origin), 'witness': witness, 'candidates': entries_out})
    return {'zones': result_zones, 'all_reachable': all(zone['reachable'] for zone in result_zones)}
