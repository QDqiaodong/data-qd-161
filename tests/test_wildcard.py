import unittest

from dns_zone_audit.model import analyze as analyze_zone
from dns_zone_audit.wildcard import analyze

SOA = {'mname': 'ns1', 'rname': 'hostmaster', 'serial': 7, 'refresh': 3600,
       'retry': 600, 'expire': 1209600, 'minimum': 300}


def rec(owner, rtype, data, ttl=None):
    return {'owner': owner, 'type': rtype, 'ttl': ttl, 'data': data}


def zone(records, origin='example.test.', default_ttl=3600):
    return {'origin': origin, 'default_ttl': default_ttl, 'records': records}


def apex(origin='example.test.', ns='ns1'):
    return [rec('@', 'SOA', SOA), rec('@', 'NS', ns)]


def base(extra=()):
    return zone(apex() + [rec('ns1', 'A', '192.0.2.53')] + list(extra))


def probe(data, name):
    return next(answer for answer in analyze(data)['answers']
                if answer['query'] == (name + '.' if not name.endswith('.') else name))


class ExplicitTests(unittest.TestCase):
    def test_explicit_owner_returns_its_rrset(self):
        data = {'zone': base([rec('www', 'A', '192.0.2.1'), rec('www', 'AAAA', '2001:db8::1')]),
                'queries': ['www']}
        answer = probe(data, 'www.example.test.')
        self.assertEqual(answer['state'], 'explicit')
        self.assertEqual(answer['closest_encloser'], 'www.example.test.')
        self.assertEqual(answer['source_owner'], 'www.example.test.')
        self.assertEqual([r['type'] for r in answer['records']], ['A', 'AAAA'])
        for record in answer['records']:
            self.assertEqual(record['owner'], 'www.example.test.')
            self.assertEqual(record['source_owner'], 'www.example.test.')

    def test_explicit_sorts_by_type_then_rdata(self):
        data = {'zone': base([rec('www', 'A', '192.0.2.9'), rec('www', 'A', '192.0.2.1'),
                              rec('www', 'TXT', 'zzz')]),
                'queries': ['www']}
        records = probe(data, 'www.example.test.')['records']
        self.assertEqual([r['data'] for r in records if r['type'] == 'A'], ['192.0.2.1', '192.0.2.9'])

    def test_explicit_beats_wildcard_parent(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10'), rec('www', 'TXT', 'explicit')]),
                'queries': ['www']}
        answer = probe(data, 'www.example.test.')
        self.assertEqual(answer['state'], 'explicit')
        self.assertEqual([r['type'] for r in answer['records']], ['TXT'])


class DelegationTests(unittest.TestCase):
    def test_strict_descendant_of_delegation_is_delegated_without_parent_wildcard(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10'), rec('branch', 'NS', 'ns.branch')]),
                'queries': ['x.branch']}
        answer = probe(data, 'x.branch.example.test.')
        self.assertEqual(answer['state'], 'delegated')
        self.assertEqual(answer['closest_encloser'], 'branch.example.test.')
        self.assertIsNone(answer['source_owner'])
        self.assertEqual(answer['records'], [])

    def test_delegation_owner_returns_explicit_ns_rrset(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10'), rec('branch', 'NS', 'ns.branch')]),
                'queries': ['branch']}
        answer = probe(data, 'branch.example.test.')
        self.assertEqual(answer['state'], 'explicit')
        self.assertEqual([r['type'] for r in answer['records']], ['NS'])
        self.assertEqual(answer['source_owner'], 'branch.example.test.')

    def test_delegated_beats_empty_non_terminal(self):
        # deep.branch is an implicit node derived from host.deep.branch, but
        # as a strict descendant of the delegation boundary it is delegated.
        data = {'zone': base([rec('branch', 'NS', 'ns.branch'),
                              rec('host.deep.branch', 'TXT', 'x')]),
                'queries': ['deep.branch']}
        answer = probe(data, 'deep.branch.example.test.')
        self.assertEqual(answer['state'], 'delegated')
        self.assertEqual(answer['closest_encloser'], 'branch.example.test.')

    def test_nearest_nested_delegation_wins(self):
        data = {'zone': base([rec('branch', 'NS', 'ns.branch'),
                              rec('sub.branch', 'NS', 'ns.sub.branch')]),
                'queries': ['x.sub.branch']}
        answer = probe(data, 'x.sub.branch.example.test.')
        self.assertEqual(answer['state'], 'delegated')
        self.assertEqual(answer['closest_encloser'], 'sub.branch.example.test.')

    def test_delegated_record_explicit_data_ignored_below_boundary(self):
        # Records below a delegation are not authoritative; a probe exactly at
        # their owner still reads the parent snapshot's explicit RRset, but a
        # probe below the boundary never wildcard-synthesizes.
        data = {'zone': base([rec('branch', 'NS', 'ns.branch'),
                              rec('x.branch', 'A', '192.0.2.77')]),
                'queries': ['x.branch', 'y.branch']}
        self.assertEqual(probe(data, 'x.branch.example.test.')['state'], 'explicit')
        self.assertEqual(probe(data, 'y.branch.example.test.')['state'], 'delegated')


class EmptyNonTerminalTests(unittest.TestCase):
    def test_implicit_node_blocks_higher_wildcard(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10'),
                              rec('host.branch', 'TXT', 'x')]),
                'queries': ['branch', 'x.branch']}
        branch = probe(data, 'branch.example.test.')
        self.assertEqual(branch['state'], 'empty_non_terminal')
        self.assertEqual(branch['closest_encloser'], 'branch.example.test.')
        self.assertIsNone(branch['source_owner'])
        self.assertEqual(branch['records'], [])
        # No *.branch, so the wildcard at the apex must not answer.
        x = probe(data, 'x.branch.example.test.')
        self.assertEqual(x['state'], 'no_match')
        self.assertEqual(x['closest_encloser'], 'branch.example.test.')

    def test_query_exactly_at_empty_non_terminal(self):
        data = {'zone': base([rec('a.b.c', 'A', '192.0.2.1')]),
                'queries': ['b.c', 'a.b.c']}
        self.assertEqual(probe(data, 'b.c.example.test.')['state'], 'empty_non_terminal')
        self.assertEqual(probe(data, 'a.b.c.example.test.')['state'], 'explicit')

    def test_recordless_apex_is_an_empty_non_terminal(self):
        data = {'zone': zone([rec('host', 'A', '192.0.2.1')]), 'queries': ['@', 'missing']}
        apex_answer = probe(data, 'example.test.')
        self.assertEqual(apex_answer['state'], 'empty_non_terminal')
        self.assertEqual(apex_answer['closest_encloser'], 'example.test.')
        # Without an apex RRset the highest existing node is `host`, so a
        # sibling name has no wildcard anywhere.
        self.assertEqual(probe(data, 'missing.example.test.')['state'], 'no_match')


class WildcardTests(unittest.TestCase):
    def test_apex_wildcard_synthesizes_unknown_name(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10')]), 'queries': ['missing']}
        answer = probe(data, 'missing.example.test.')
        self.assertEqual(answer['state'], 'wildcard')
        self.assertEqual(answer['closest_encloser'], 'example.test.')
        self.assertEqual(answer['source_owner'], '*.example.test.')
        self.assertEqual(len(answer['records']), 1)
        record = answer['records'][0]
        self.assertEqual(record['owner'], 'missing.example.test.')
        self.assertEqual(record['source_owner'], '*.example.test.')
        self.assertEqual(record['data'], '192.0.2.10')
        self.assertEqual(record['ttl'], 3600)

    def test_nearest_encloser_wildcard_is_used_not_higher_ancestor(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10'),
                              rec('host.branch', 'TXT', 'x'),
                              rec('*.branch', 'A', '192.0.2.20')]),
                'queries': ['x.branch']}
        answer = probe(data, 'x.branch.example.test.')
        self.assertEqual(answer['state'], 'wildcard')
        self.assertEqual(answer['closest_encloser'], 'branch.example.test.')
        self.assertEqual(answer['source_owner'], '*.branch.example.test.')
        self.assertEqual(answer['records'][0]['owner'], 'x.branch.example.test.')
        self.assertEqual(answer['records'][0]['data'], '192.0.2.20')
        self.assertEqual(answer['records'][0]['ttl'], 3600)

    def test_no_fallback_to_higher_wildcard_when_nearest_lacks_one(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10'),
                              rec('host.ops.branch', 'TXT', 'x')]),
                'queries': ['other.ops.branch']}
        # closest encloser is ops.branch (derived), which has no *.ops.branch
        answer = probe(data, 'other.ops.branch.example.test.')
        self.assertEqual(answer['state'], 'no_match')
        self.assertEqual(answer['closest_encloser'], 'ops.branch.example.test.')
        self.assertIsNone(answer['source_owner'])
        self.assertEqual(answer['records'], [])

    def test_no_wildcard_means_no_match(self):
        data = {'zone': base([rec('web', 'A', '192.0.2.1')]), 'queries': ['missing']}
        answer = probe(data, 'missing.example.test.')
        self.assertEqual(answer['state'], 'no_match')
        self.assertEqual(answer['closest_encloser'], 'example.test.')
        self.assertEqual(answer['records'], [])

    def test_wildcard_ttl_and_rdata_are_preserved(self):
        data = {'zone': zone(apex() + [rec('ns1', 'A', '192.0.2.53'),
                                       rec('*', 'MX', {'preference': 10, 'exchange': 'mail'}, ttl=55)]),
                'queries': ['anything']}
        record = probe(data, 'anything.example.test.')['records'][0]
        self.assertEqual(record['ttl'], 55)
        self.assertEqual(record['data'], {'preference': 10, 'exchange': 'mail.example.test.'})
        self.assertEqual(record['owner'], 'anything.example.test.')
        self.assertEqual(record['source_owner'], '*.example.test.')

    def test_apex_query_uses_explicit_apex_never_wildcard(self):
        data = {'zone': base([rec('*', 'A', '192.0.2.10')]), 'queries': ['@']}
        answer = probe(data, 'example.test.')
        self.assertEqual(answer['state'], 'explicit')
        self.assertEqual({r['type'] for r in answer['records']}, {'SOA', 'NS'})


class CnameTests(unittest.TestCase):
    def test_wildcard_cname_returned_but_not_followed(self):
        data = {'zone': base([rec('*', 'CNAME', 'target'), rec('target', 'A', '192.0.2.99')]),
                'queries': ['alias']}
        answer = probe(data, 'alias.example.test.')
        self.assertEqual(answer['state'], 'wildcard')
        self.assertEqual(len(answer['records']), 1)
        record = answer['records'][0]
        self.assertEqual(record['type'], 'CNAME')
        self.assertEqual(record['data'], 'target.example.test.')
        self.assertEqual(record['owner'], 'alias.example.test.')
        self.assertEqual(record['source_owner'], '*.example.test.')

    def test_explicit_cname_not_followed(self):
        data = {'zone': base([rec('alias', 'CNAME', 'target'), rec('target', 'A', '192.0.2.99')]),
                'queries': ['alias']}
        answer = probe(data, 'alias.example.test.')
        self.assertEqual(answer['state'], 'explicit')
        self.assertEqual([r['type'] for r in answer['records']], ['CNAME'])


class OrderingAndNormalizationTests(unittest.TestCase):
    def test_query_order_does_not_change_result(self):
        records = [rec('*', 'A', '192.0.2.10'), rec('host.branch', 'TXT', 'x'),
                   rec('*.branch', 'A', '192.0.2.20'), rec('child', 'NS', 'ns.child')]
        queries = ['x.branch', 'missing', 'host.branch', 'child', 'x.child']
        forward = analyze({'zone': base(records), 'queries': queries})
        backward = analyze({'zone': base(records), 'queries': list(reversed(queries))})
        self.assertEqual(forward, backward)
        self.assertEqual([a['query'] for a in forward['answers']],
                         sorted(a['query'] for a in forward['answers']))

    def test_record_order_does_not_change_result(self):
        records = [rec('*', 'A', '192.0.2.10'), rec('www', 'A', '192.0.2.1'),
                   rec('www', 'AAAA', '2001:db8::1')]
        forward = analyze({'zone': base(records), 'queries': ['www', 'other']})
        backward = analyze({'zone': base(list(reversed(records))), 'queries': ['other', 'www']})
        self.assertEqual(forward, backward)

    def test_relative_absolute_at_case_and_ipv6_normalization(self):
        canonical = analyze({'zone': base([rec('*', 'A', '192.0.2.10')]), 'queries': ['x', '@']})
        variant = analyze({'zone': zone(apex('EXAMPLE.TEST.') + [
            rec('NS1', 'A', '192.0.2.53'), rec('*', 'A', '192.0.2.10')], origin='Example.Test.'),
            'queries': ['X.Example.Test.', 'Example.Test.']})
        self.assertEqual(canonical, variant)

    def test_result_shape_is_strict(self):
        result = analyze({'zone': base([rec('*', 'A', '192.0.2.10')]), 'queries': ['x']})
        self.assertEqual(set(result), {'origin', 'answers'})
        for answer in result['answers']:
            self.assertEqual(set(answer), {'query', 'state', 'closest_encloser',
                                           'source_owner', 'records'})
            for record in answer['records']:
                self.assertEqual(set(record), {'owner', 'source_owner', 'type', 'ttl', 'data'})


class ContractTests(unittest.TestCase):
    def test_query_limits(self):
        data = {'zone': base(), 'queries': []}
        with self.assertRaisesRegex(ValueError, 'queries'):
            analyze(data)
        many = ['h%d' % i for i in range(1001)]
        with self.assertRaises(ValueError):
            analyze({'zone': base(), 'queries': many})
        result = analyze({'zone': base(), 'queries': ['h%d' % i for i in range(1000)]})
        self.assertEqual(len(result['answers']), 1000)

    def test_top_level_fields_strict(self):
        for bad in ({'zone': base()},
                    {'zone': base(), 'queries': ['x'], 'extra': 1},
                    {'queries': ['x']}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    analyze(bad)

    def test_duplicate_query_after_normalization(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            analyze({'zone': base(), 'queries': ['www', 'WWW.example.test.']})

    def test_query_outside_zone_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside zone'):
            analyze({'zone': base(), 'queries': ['www.other.test.']})

    def test_query_wildcard_label_rejected(self):
        for bad in ('*', '*.branch', 'x.*'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    analyze({'zone': base(), 'queries': [bad]})

    def test_only_complete_first_label_star_is_a_wildcard_owner(self):
        for bad in ('a.*', '*a', 'a*b', '*.*', 'x.*.y', '**'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    analyze_zone(zone(apex() + [rec(bad, 'A', '192.0.2.1')]))

    def test_wildcard_in_rdata_rejected(self):
        for kind, data in (('CNAME', '*'), ('NS', '*.ns'), ('MX', {'preference': 1, 'exchange': '*'})):
            with self.subTest(kind=kind):
                records = apex() + [rec('x', kind, data)]
                if kind == 'NS':
                    records.append(rec('*', 'A', '192.0.2.10'))
                with self.assertRaises(ValueError):
                    analyze_zone(zone(records))

    def test_wildcard_owner_normalizes_and_remains_star(self):
        audit = analyze_zone(zone(apex() + [rec('*', 'A', '192.0.2.10'),
                                           rec('*.Basic', 'TXT', 'x')]))
        owners = {r['owner'] for r in audit['records']}
        self.assertIn('*.example.test.', owners)
        self.assertIn('*.basic.example.test.', owners)

    def test_wildcard_owner_does_not_change_single_zone_record_count(self):
        # The shared model accepts a wildcard owner without altering the
        # single-zone audit's record grouping or findings semantics.
        report = analyze_zone(zone(apex() + [rec('*', 'A', '192.0.2.10')]))
        self.assertEqual(report['record_count'], 3)


if __name__ == '__main__':
    unittest.main()
