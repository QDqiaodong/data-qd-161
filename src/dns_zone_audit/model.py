import ipaddress
import re
from .common import require, ident, number, rows


def dns_name(value, origin):
    ident(value)
    if value == '@':
        return origin
    absolute = value.endswith('.')
    name = value[:-1] if absolute else value
    if not absolute:
        name = name + '.' + origin[:-1]
    name = name.lower() + '.'
    labels = name[:-1].split('.')
    if len(name) > 255 or any(len(label) > 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label) for label in labels):
        raise ValueError('invalid DNS name')
    return name


def analyze(data):
    require(data, 'origin default_ttl records')
    raw_origin = ident(data['origin'])
    origin = dns_name(raw_origin.rstrip('.') + '.', raw_origin.rstrip('.') + '.')
    ttl = number(data['default_ttl'], 0, 2147483647)
    records = []
    identities = set()
    for raw in rows(data['records'], 10000):
        if not isinstance(raw, dict):
            raise ValueError('record object required')
        require(raw, 'owner type ttl data')
        owner = dns_name(raw['owner'], origin)
        if owner != origin and not owner.endswith('.' + origin):
            raise ValueError('record owner outside zone')
        kind = raw['type']
        if kind not in ('SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'TXT'):
            raise ValueError('unsupported record type')
        rttl = ttl if raw['ttl'] is None else number(raw['ttl'], 0, 2147483647)
        value = raw['data']
        if kind in ('NS', 'CNAME'):
            value = dns_name(value, origin)
        elif kind == 'A':
            value = str(ipaddress.IPv4Address(value))
        elif kind == 'AAAA':
            value = str(ipaddress.IPv6Address(value))
        elif kind == 'MX':
            require(value, 'preference exchange')
            value = {'preference': number(value['preference'], 0, 65535), 'exchange': dns_name(value['exchange'], origin)}
        elif kind == 'SOA':
            require(value, 'mname rname serial refresh retry expire minimum')
            value = {'mname': dns_name(value['mname'], origin), 'rname': dns_name(value['rname'], origin)}
            for field, maximum in [('serial', 4294967295), ('refresh', 2147483647), ('retry', 2147483647), ('expire', 2147483647), ('minimum', 2147483647)]:
                value[field] = number(raw['data'][field], 0, maximum)
        elif kind == 'TXT':
            if not isinstance(value, str) or len(value.encode('utf-8')) > 255:
                raise ValueError('TXT data must be a UTF-8 string of at most 255 bytes')
        identity = (owner, kind, repr(value))
        if identity in identities:
            raise ValueError('duplicate DNS record')
        identities.add(identity)
        records.append({'owner': owner, 'type': kind, 'ttl': rttl, 'data': value})

    by_owner = {}
    for record in records:
        by_owner.setdefault(record['owner'], []).append(record)
    issues = []
    apex = by_owner.get(origin, [])
    if sum(r['type'] == 'SOA' for r in apex) != 1:
        issues.append({'code': 'apex_soa_count', 'owner': origin, 'count': sum(r['type'] == 'SOA' for r in apex)})
    if not any(r['type'] == 'NS' for r in apex):
        issues.append({'code': 'apex_ns_missing', 'owner': origin})
    for owner, owner_records in sorted(by_owner.items()):
        types = {r['type'] for r in owner_records}
        if 'CNAME' in types and len(types) > 1:
            issues.append({'code': 'cname_exclusive_conflict', 'owner': owner, 'types': sorted(types)})
    aliases = {r['owner'] for r in records if r['type'] == 'CNAME'}
    for record in records:
        if record['type'] == 'MX' and record['data']['exchange'] in aliases:
            issues.append({'code': 'mx_target_is_alias', 'owner': record['owner'], 'target': record['data']['exchange']})
    delegations = {r['owner'] for r in records if r['type'] == 'NS' and r['owner'] != origin}
    for child in sorted(delegations):
        targets = {r['data'] for r in by_owner.get(child, []) if r['type'] == 'NS'}
        for target in sorted(targets):
            in_zone = target == origin or target.endswith('.' + origin)
            if in_zone and not any(r['type'] in ('A', 'AAAA') for r in by_owner.get(target, [])):
                issues.append({'code': 'in_zone_glue_missing', 'owner': child, 'target': target})
    return {'origin': origin, 'record_count': len(records), 'records': sorted(records, key=lambda r: (r['owner'], r['type'], repr(r['data']))), 'issues': issues, 'valid': not issues}
