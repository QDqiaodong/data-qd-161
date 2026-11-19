import json
import unittest
from pathlib import Path

from dns_zone_audit.model import analyze as analyze_zone
from dns_zone_audit.redact import analyze

ROOT = Path(__file__).resolve().parents[1]

SOA = {'mname': 'ns1', 'rname': 'hostmaster', 'serial': 7, 'refresh': 3600,
       'retry': 600, 'expire': 1209600, 'minimum': 300}

APEX = {'space': 'zone', 'path': []}


def rec(owner, rtype, data, ttl=None):
    return {'owner': owner, 'type': rtype, 'ttl': ttl, 'data': data}


def zone(records, origin='example.test.', default_ttl=3600):
    return {'origin': origin, 'default_ttl': default_ttl, 'records': records}


def apex(origin='example.test.', ns='ns1'):
    return [rec('@', 'SOA', SOA), rec('@', 'NS', ns)]


def base(extra=()):
    return zone(apex() + [rec('ns1', 'A', '192.0.2.53')] + list(extra))


def find_name(result, alias):
    matches = [entry for entry in result['names'] if entry['name'] == alias]
    assert len(matches) <= 1, 'alias listed more than once'
    return matches[0] if matches else None


def only_group(result, rtype, owner=None):
    matches = [group for group in result['groups'] if group['type'] == rtype
               and (owner is None or group['owner'] == owner)]
    assert len(matches) == 1, 'expected exactly one %s group' % rtype
    return matches[0]


class GroupingTests(unittest.TestCase):
    def test_apex_mx_pair_collapses_and_points_at_mail_owner(self):
        # Acceptance linkage: two apex MX records differing only in
        # preference (and TTL) form one count-2 group whose exchange alias
        # is the alias of the A-record owner mail.ops.
        result = analyze(zone(apex() + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('@', 'MX', {'preference': 10, 'exchange': 'mail.ops'}),
            rec('@', 'MX', {'preference': 20, 'exchange': 'mail.ops'}, ttl=7200),
            rec('mail.ops', 'A', '192.0.2.25'),
        ]))
        group = only_group(result, 'MX', APEX)
        self.assertEqual(group['count'], 2)
        self.assertEqual(set(group['targets']), {'exchange'})
        exchange = group['targets']['exchange']
        self.assertEqual(exchange['space'], 'zone')
        self.assertEqual(len(exchange['path']), 2)
        self.assertTrue(find_name(result, exchange)['has_records'])
        # The exchange alias is exactly the A-record owner's alias.
        self.assertEqual(only_group(result, 'A', exchange)['count'], 1)

    def test_same_owner_address_records_share_one_group(self):
        result = analyze(base([
            rec('www', 'A', '192.0.2.1'),
            rec('www', 'A', '192.0.2.2', ttl=60),
            rec('www', 'TXT', 'first'),
            rec('www', 'TXT', 'second'),
        ]))
        www = find_name(result, only_group(result, 'TXT')['owner'])
        self.assertTrue(www['has_records'])
        self.assertEqual(only_group(result, 'TXT')['count'], 2)
        self.assertEqual(only_group(result, 'TXT')['targets'], {})
        a_groups = [g for g in result['groups']
                    if g['type'] == 'A' and g['owner'] == www['name']]
        self.assertEqual(len(a_groups), 1)
        self.assertEqual(a_groups[0]['count'], 2)

    def test_every_record_counted_exactly_once(self):
        data = base([
            rec('www', 'A', '192.0.2.1'), rec('www', 'A', '192.0.2.2'),
            rec('www', 'TXT', 'a'), rec('www', 'TXT', 'b'),
            rec('@', 'MX', {'preference': 10, 'exchange': 'mail'}),
            rec('@', 'MX', {'preference': 20, 'exchange': 'mail'}),
            rec('mail', 'AAAA', '2001:db8::25'),
        ])
        result = analyze(data)
        self.assertEqual(sum(g['count'] for g in result['groups']),
                         analyze_zone(data)['record_count'])


class NameTableTests(unittest.TestCase):
    def test_cname_target_is_proper_prefix_of_descendant_owner(self):
        # Acceptance linkage: alias.ops CNAME -> ghost.ops (no records)
        # while leaf.ghost.ops owns TXT; the target path is a proper
        # prefix of the leaf path and the target stays recordless.
        result = analyze(base([
            rec('alias.ops', 'CNAME', 'ghost.ops'),
            rec('leaf.ghost.ops', 'TXT', 'note'),
        ]))
        target = only_group(result, 'CNAME')['targets']['target']
        self.assertEqual(target['space'], 'zone')
        target_entry = find_name(result, target)
        self.assertIsNotNone(target_entry)
        self.assertFalse(target_entry['has_records'])
        leaf = only_group(result, 'TXT')['owner']
        self.assertLess(len(target['path']), len(leaf['path']))
        self.assertEqual(leaf['path'][:len(target['path'])], target['path'])

    def test_pure_intermediate_paths_are_not_listed(self):
        result = analyze(base([rec('leaf.ghost.ops', 'TXT', 'x')]))
        zone_paths = [entry['name']['path'] for entry in result['names']
                      if entry['name']['space'] == 'zone']
        leaf = next(path for path in zone_paths if len(path) == 3)
        self.assertNotIn(leaf[:2], zone_paths)  # ghost.ops: no record, no reference
        self.assertNotIn(leaf[:1], zone_paths)  # ops: pure intermediate
        self.assertIn([], zone_paths)           # the apex is always listed

    def test_apex_without_records_is_listed_without_records(self):
        data = zone([rec('host', 'A', '192.0.2.1')])
        self.assertFalse(analyze_zone(data)['valid'])  # findings never block export
        result = analyze(data)
        apex_entry = find_name(result, APEX)
        self.assertIsNotNone(apex_entry)
        self.assertFalse(apex_entry['has_records'])
        self.assertTrue(all(group['owner'] != APEX for group in result['groups']))

    def test_wildcard_owner_keeps_star_step_and_sorts_before_integers(self):
        result = analyze(base([
            rec('*.ops', 'A', '192.0.2.10'),
            rec('a.ops', 'TXT', 'x'),
        ]))
        star = next(entry for entry in result['names'] if '*' in entry['name']['path'])
        self.assertEqual(star['name']['space'], 'zone')
        self.assertEqual(star['name']['path'][-1], '*')
        self.assertEqual(len(star['name']['path']), 2)
        self.assertTrue(star['has_records'])
        sibling = next(entry for entry in result['names']
                       if entry['name']['space'] == 'zone'
                       and entry['name']['path'][:-1] == star['name']['path'][:-1]
                       and entry['name'] != star['name'])
        zone_paths = [entry['name']['path'] for entry in result['names']
                      if entry['name']['space'] == 'zone']
        self.assertLess(zone_paths.index(star['name']['path']),
                        zone_paths.index(sibling['name']['path']))

    def test_aliases_are_unique_and_shared_with_groups(self):
        result = analyze(base([
            rec('alias.ops', 'CNAME', 'ghost.ops'),
            rec('leaf.ghost.ops', 'TXT', 'x'),
            rec('www', 'CNAME', 'web.external-cdn.net.'),
        ]))
        rendered = [json.dumps(entry['name'], sort_keys=True) for entry in result['names']]
        self.assertEqual(len(rendered), len(set(rendered)))
        table = set(rendered)
        for group in result['groups']:
            self.assertIn(json.dumps(group['owner'], sort_keys=True), table)
            for alias in group['targets'].values():
                self.assertIn(json.dumps(alias, sort_keys=True), table)


class ExternalNameTests(unittest.TestCase):
    def test_external_near_suffix_is_not_in_zone(self):
        # ns.notexample.test. ends with the apex text but not on a label
        # boundary, so it belongs to the external space with its full path.
        result = analyze(base([rec('child', 'NS', 'ns.notexample.test.')]))
        group = next(g for g in result['groups']
                     if g['type'] == 'NS' and g['owner'] != APEX)
        target = group['targets']['target']
        self.assertEqual(target['space'], 'external')
        self.assertEqual(len(target['path']), 3)  # test / notexample / ns
        entry = find_name(result, target)
        self.assertIsNotNone(entry)
        self.assertFalse(entry['has_records'])

    def test_external_path_encodes_the_full_name(self):
        result = analyze(base([rec('www', 'CNAME', 'a.b.cdnhide.net.')]))
        target = only_group(result, 'CNAME')['targets']['target']
        self.assertEqual(target['space'], 'external')
        self.assertEqual(len(target['path']), 4)  # net / cdnhide / b / a

    def test_spaces_are_disjoint_namespaces(self):
        # The same label below the apex and below an external parent yields
        # unrelated aliases in disjoint spaces.
        result = analyze(zone([
            rec('@', 'SOA', {'mname': 'ops', 'rname': 'ops', 'serial': 7,
                             'refresh': 3600, 'retry': 600, 'expire': 1209600,
                             'minimum': 300}),
            rec('@', 'NS', 'ops'),
            rec('ops', 'A', '192.0.2.1'),
            rec('www', 'CNAME', 'ops.otherhide.net.'),
        ]))
        in_zone = only_group(result, 'A')['owner']
        external = only_group(result, 'CNAME')['targets']['target']
        self.assertEqual(in_zone['space'], 'zone')
        self.assertEqual(external['space'], 'external')
        self.assertEqual(len(in_zone['path']), 1)
        self.assertEqual(len(external['path']), 3)


class SoaRoleTests(unittest.TestCase):
    def test_soa_roles_share_one_target_alias(self):
        result = analyze(zone([
            rec('@', 'SOA', {'mname': 'ns1', 'rname': 'ns1', 'serial': 7,
                             'refresh': 3600, 'retry': 600, 'expire': 1209600,
                             'minimum': 300}),
            rec('@', 'NS', 'ns1'),
            rec('ns1', 'A', '192.0.2.53'),
        ]))
        group = only_group(result, 'SOA', APEX)
        self.assertEqual(set(group['targets']), {'mname', 'rname'})
        self.assertEqual(group['targets']['mname'], group['targets']['rname'])
        shared = group['targets']['mname']
        self.assertTrue(find_name(result, shared)['has_records'])
        # The NS target of the apex resolves to the very same alias.
        self.assertEqual(only_group(result, 'NS', APEX)['targets']['target'], shared)


class InvarianceTests(unittest.TestCase):
    def records(self):
        return [
            rec('@', 'SOA', SOA),
            rec('@', 'NS', 'ns1.ops'),
            rec('@', 'MX', {'preference': 10, 'exchange': 'mail.ops'}),
            rec('@', 'MX', {'preference': 20, 'exchange': 'mail.ops'}, ttl=7200),
            rec('ns1.ops', 'A', '192.0.2.53'),
            rec('mail.ops', 'A', '192.0.2.25'),
            rec('alias.ops', 'CNAME', 'ghost.ops'),
            rec('leaf.ghost.ops', 'TXT', 'note'),
            rec('*.ops', 'A', '192.0.2.99'),
            rec('www', 'CNAME', 'web.external-cdn.net.'),
        ]

    def test_record_order_spelling_case_and_ttl_invariance(self):
        canonical = analyze(zone(self.records()))
        variant = analyze(zone([
            rec('WWW', 'CNAME', 'Web.External-CDN.Net.', ttl=5),
            rec('*.OPS', 'A', '192.0.2.99', ttl=5),
            rec('Leaf.Ghost.Ops', 'TXT', 'note', ttl=5),
            rec('Alias.Ops', 'CNAME', 'GHOST.ops', ttl=5),
            rec('MAIL.OPS', 'A', '192.0.2.25', ttl=5),
            rec('@', 'MX', {'preference': 20, 'exchange': 'Mail.Ops'}, ttl=5),
            rec('@', 'MX', {'preference': 10, 'exchange': 'MAIL.ops.example.test.'}, ttl=5),
            rec('NS1.ops', 'A', '192.0.2.53', ttl=5),
            rec('Example.Test.', 'NS', 'NS1.ops', ttl=5),
            rec('@', 'SOA', {'mname': 'NS1', 'rname': 'HOSTMASTER',
                             'serial': 99, 'refresh': 1, 'retry': 2,
                             'expire': 3, 'minimum': 4}, ttl=5),
        ], origin='EXAMPLE.TEST.', default_ttl=60))
        self.assertEqual(canonical, variant)

    def test_rerun_is_identical(self):
        self.assertEqual(analyze(zone(self.records())), analyze(zone(self.records())))


class RedactionTests(unittest.TestCase):
    def test_sensitive_payload_never_appears_in_result(self):
        data = zone([
            rec('@', 'SOA', {'mname': 'hiddenns', 'rname': 'hiddenhostmaster',
                             'serial': 4000000001, 'refresh': 46113, 'retry': 9021,
                             'expire': 2419200, 'minimum': 612}),
            rec('@', 'NS', 'hiddenns', ttl=654321),
            rec('hiddenns', 'A', '192.0.2.77'),
            rec('secrethost', 'TXT', 'topsecretpayload'),
            rec('@', 'MX', {'preference': 43210, 'exchange': 'mailhide'}),
            rec('mailhide', 'AAAA', '2001:db8::25'),
            rec('alias', 'CNAME', 'targethide.cdnhide.net.'),
        ])
        text = json.dumps(analyze(data))
        for needle in ('hiddenns', 'hiddenhostmaster', 'secrethost', 'secret',
                       'topsecretpayload', '192.0.2.77', '2001:db8', '43210',
                       '654321', '4000000001', '46113', '2419200',
                       'mailhide', 'targethide', 'cdnhide'):
            with self.subTest(needle=needle):
                self.assertNotIn(needle, text)

    def test_result_shape_is_strict(self):
        result = analyze(base([rec('www', 'A', '192.0.2.1')]))
        self.assertEqual(set(result), {'names', 'groups'})
        for entry in result['names']:
            self.assertEqual(set(entry), {'name', 'has_records'})
            self.assertEqual(set(entry['name']), {'space', 'path'})
            self.assertIn(entry['name']['space'], ('zone', 'external'))
            self.assertIsInstance(entry['has_records'], bool)
            for step in entry['name']['path']:
                self.assertTrue(step == '*' or (type(step) is int and step >= 1))
        for group in result['groups']:
            self.assertEqual(set(group), {'owner', 'type', 'targets', 'count'})
            self.assertEqual(set(group['owner']), {'space', 'path'})
            self.assertIn(group['type'], ('SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'TXT'))
            self.assertIs(type(group['count']), int)
            self.assertGreaterEqual(group['count'], 1)
            for alias in group['targets'].values():
                self.assertEqual(set(alias), {'space', 'path'})

    def test_invalid_snapshots_are_rejected(self):
        duplicate = base([rec('www', 'A', '192.0.2.1'), rec('WWW', 'A', '192.0.2.1')])
        for bad in ({},
                    {'origin': 'example.test.', 'default_ttl': 3600},
                    zone([rec('x', 'SRV', 'y')]),
                    zone([rec('x', 'A', '192.0.2.999')]),
                    zone([rec('x', 'A', '192.0.2.1', ttl=-1)]),
                    zone([rec('x.other.test.', 'A', '192.0.2.1')]),
                    duplicate):
            with self.subTest(bad=str(bad)[:60]):
                with self.assertRaises(ValueError):
                    analyze(bad)


class OrderingTests(unittest.TestCase):
    def test_names_and_groups_follow_contract_order(self):
        result = analyze(base([
            rec('*.ops', 'A', '192.0.2.10'),
            rec('a.ops', 'TXT', 'x'),
            rec('leaf.ghost.ops', 'TXT', 'y'),
            rec('alias.ops', 'CNAME', 'ghost.ops'),
            rec('www', 'CNAME', 'web.external-cdn.net.'),
        ]))
        # Zone root children sorted: hostmaster=1, ns1=2, ops=3, www=4;
        # below ops: a=1, alias=2, ghost=3; external: net=1, cdn=1, web=1.
        expected_names = [
            ('external', [1, 1, 1], False),   # web.external-cdn.net.
            ('zone', [], True),               # apex
            ('zone', [1], False),             # hostmaster (SOA rname only)
            ('zone', [2], True),              # ns1
            ('zone', [3, '*'], True),         # *.ops: "*" before integers
            ('zone', [3, 1], True),           # a.ops
            ('zone', [3, 2], True),           # alias.ops
            ('zone', [3, 3], False),          # ghost.ops: referenced only
            ('zone', [3, 3, 1], True),        # leaf.ghost.ops
            ('zone', [4], True),              # www
        ]
        actual = [(e['name']['space'], e['name']['path'], e['has_records'])
                  for e in result['names']]
        self.assertEqual(actual, expected_names)
        expected_groups = [
            ([], 'NS', {'target': ('zone', [2])}, 1),
            ([], 'SOA', {'mname': ('zone', [2]), 'rname': ('zone', [1])}, 1),
            ([2], 'A', {}, 1),
            ([3, '*'], 'A', {}, 1),
            ([3, 1], 'TXT', {}, 1),
            ([3, 2], 'CNAME', {'target': ('zone', [3, 3])}, 1),
            ([3, 3, 1], 'TXT', {}, 1),
            ([4], 'CNAME', {'target': ('external', [1, 1, 1])}, 1),
        ]
        actual_groups = [
            (g['owner']['path'], g['type'],
             {role: (a['space'], a['path']) for role, a in g['targets'].items()},
             g['count'])
            for g in result['groups']
        ]
        self.assertEqual(actual_groups, expected_groups)


class FixtureTests(unittest.TestCase):
    def test_fixture_export_matches_expected_structure(self):
        data = json.loads((ROOT / 'fixtures/redact-input.json').read_text())
        self.assertTrue(analyze_zone(data)['valid'])
        result = analyze(data)
        expected_names = [
            ('external', [1, 1, 1], False),   # web.external-cdn.net.
            ('external', [1, 2, 1], False),   # hostmaster.external-mail.net.
            ('zone', [], True),               # apex
            ('zone', [1, '*'], True),         # *.ops
            ('zone', [1, 1], True),           # alias.ops
            ('zone', [1, 2], False),          # ghost.ops: referenced only
            ('zone', [1, 2, 1], True),        # leaf.ghost.ops
            ('zone', [1, 3], True),           # mail.ops
            ('zone', [1, 4], True),           # ns1.ops
            ('zone', [2], True),              # www
        ]
        actual = [(e['name']['space'], e['name']['path'], e['has_records'])
                  for e in result['names']]
        self.assertEqual(actual, expected_names)
        expected_groups = [
            ([], 'MX', {'exchange': ('zone', [1, 3])}, 2),
            ([], 'NS', {'target': ('zone', [1, 4])}, 1),
            ([], 'SOA', {'mname': ('zone', [1, 4]),
                         'rname': ('external', [1, 2, 1])}, 1),
            ([1, '*'], 'A', {}, 1),
            ([1, 1], 'CNAME', {'target': ('zone', [1, 2])}, 1),
            ([1, 2, 1], 'TXT', {}, 1),
            ([1, 3], 'A', {}, 1),
            ([1, 4], 'A', {}, 1),
            ([2], 'CNAME', {'target': ('external', [1, 1, 1])}, 1),
        ]
        actual_groups = [
            (g['owner']['path'], g['type'],
             {role: (a['space'], a['path']) for role, a in g['targets'].items()},
             g['count'])
            for g in result['groups']
        ]
        self.assertEqual(actual_groups, expected_groups)
        self.assertEqual(sum(g['count'] for g in result['groups']),
                         len(data['records']))


if __name__ == '__main__':
    unittest.main()
