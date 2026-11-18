import unittest
from dns_zone_audit.bootstrap import analyze

SOA = {'mname': 'ns1', 'rname': 'hostmaster', 'serial': 7, 'refresh': 3600,
       'retry': 600, 'expire': 1209600, 'minimum': 300}


def rec(owner, rtype, data, ttl=None):
    return {'owner': owner, 'type': rtype, 'ttl': ttl, 'data': data}


def zone(origin, records, default_ttl=3600):
    return {'origin': origin, 'default_ttl': default_ttl, 'records': records}


def apex(ns='ns'):
    return [rec('@', 'SOA', SOA), rec('@', 'NS', ns)]


def cycle(extra_root_records=None):
    """Root example.test. with sibling zones a and b that cross-depend."""
    root = zone('example.test.', apex('ns1') + [
        rec('ns1', 'A', '192.0.2.53'),
        rec('a', 'NS', 'ns.b'),
        rec('a', 'NS', 'boot.a'),
        rec('b', 'NS', 'ns.a'),
    ] + list(extra_root_records or []))
    za = zone('a.example.test.', apex('ns') + [
        rec('ns', 'A', '192.0.2.1'),
        rec('boot', 'A', '192.0.2.2'),
    ])
    zb = zone('b.example.test.', apex('ns') + [
        rec('ns', 'A', '192.0.2.3'),
    ])
    return {'zones': [root, za, zb], 'roots': ['example.test.']}


def entry(result, origin):
    return next(z for z in result['zones'] if z['origin'] == origin)


def candidate(zone_entry, ns):
    return next(c for c in zone_entry['candidates'] if c['ns'] == ns)


class RootLevelTests(unittest.TestCase):
    def test_single_root_zone(self):
        result = analyze({'zones': [zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53')])],
                          'roots': ['example.test.']})
        self.assertTrue(result['all_reachable'])
        self.assertEqual([z['origin'] for z in result['zones']], ['example.test.'])
        root = result['zones'][0]
        self.assertEqual(root, {'origin': 'example.test.', 'parent': None, 'reachable': True,
                                'round': 0, 'witness': None, 'candidates': []})

    def test_old_issues_do_not_reject_or_decide(self):
        # Missing apex SOA/NS and a CNAME+A conflict are local findings of the
        # single-zone audit; the bootstrap audit neither rejects nor follows them.
        root = zone('example.test.', [
            rec('child', 'NS', 'boot.child'),
            rec('boot.child', 'CNAME', 'elsewhere.example.test.'),
            rec('boot.child', 'A', '192.0.2.10'),
        ])
        child = zone('child.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.11')])
        result = analyze({'zones': [root, child], 'roots': ['example.test.']})
        child_entry = entry(result, 'child.example.test.')
        self.assertTrue(child_entry['reachable'])
        self.assertEqual(child_entry['round'], 1)
        self.assertEqual(child_entry['witness']['address'], '192.0.2.10')
        self.assertTrue(result['all_reachable'])


class CycleBreakTests(unittest.TestCase):
    def test_initial_mutual_dependency_unreachable(self):
        result = analyze(cycle())
        self.assertFalse(result['all_reachable'])
        za = entry(result, 'a.example.test.')
        zb = entry(result, 'b.example.test.')
        self.assertIsNone(za['round'])
        self.assertIsNone(zb['round'])
        self.assertIsNone(za['witness'])
        # boot.a's address inside a's own snapshot cannot bootstrap a itself.
        glue = candidate(za, 'boot.a.example.test.')
        self.assertEqual(glue['channel'], 'glue')
        self.assertEqual(glue['address_zone'], 'example.test.')
        self.assertEqual(glue['addresses'], [])
        self.assertEqual(glue['reason'], 'address_missing')
        self.assertEqual(glue['waiting_on'], [])
        self.assertFalse(glue['ready'])
        # The cross-zone addresses exist but wait on the unreachable sibling.
        ext_a = candidate(za, 'ns.b.example.test.')
        self.assertEqual(ext_a['channel'], 'authority')
        self.assertEqual(ext_a['address_zone'], 'b.example.test.')
        self.assertEqual(ext_a['addresses'], ['192.0.2.3'])
        self.assertEqual(ext_a['waiting_on'], ['b.example.test.'])
        self.assertEqual(ext_a['reason'], 'waiting')
        ext_b = candidate(zb, 'ns.a.example.test.')
        self.assertEqual(ext_b['addresses'], ['192.0.2.1'])
        self.assertEqual(ext_b['waiting_on'], ['a.example.test.'])

    def test_parent_glue_breaks_cycle_in_dependency_order(self):
        result = analyze(cycle([rec('boot.a', 'A', '192.0.2.10')]))
        self.assertTrue(result['all_reachable'])
        za = entry(result, 'a.example.test.')
        zb = entry(result, 'b.example.test.')
        self.assertEqual(za['round'], 1)
        self.assertEqual(za['witness'], {'ns': 'boot.a.example.test.', 'channel': 'glue',
                                         'address_zone': 'example.test.', 'address': '192.0.2.10'})
        self.assertEqual(zb['round'], 2)
        self.assertEqual(zb['witness'], {'ns': 'ns.a.example.test.', 'channel': 'authority',
                                         'address_zone': 'a.example.test.', 'address': '192.0.2.1'})
        # Closure final state: every sourced candidate is ready.
        for zone_entry in (za, zb):
            for cand in zone_entry['candidates']:
                self.assertTrue(cand['ready'], cand)
                self.assertEqual(cand['reason'], 'ready')

    def test_removing_glue_restores_initial_state(self):
        baseline = analyze(cycle())
        with_glue = cycle([rec('boot.a', 'A', '192.0.2.10')])
        self.assertEqual(analyze(with_glue)['all_reachable'], True)
        self.assertEqual(analyze(cycle()), baseline)

    def test_cname_only_glue_cannot_bootstrap(self):
        result = analyze(cycle([rec('boot.a', 'CNAME', 'elsewhere.example.test.')]))
        self.assertEqual(result, analyze(cycle()))

    def test_same_name_copy_in_parent_is_not_authority_source(self):
        # A non-authoritative same-name copy in the parent (glue scoped to the
        # other delegation) must not serve b's authority candidate.
        result = analyze(cycle([rec('ns.a', 'A', '192.0.2.99')]))
        zb = entry(result, 'b.example.test.')
        cand = candidate(zb, 'ns.a.example.test.')
        self.assertEqual(cand['addresses'], ['192.0.2.1'])
        self.assertEqual(cand['address_zone'], 'a.example.test.')
        self.assertFalse(result['all_reachable'])


class GrandchildTests(unittest.TestCase):
    def test_parent_and_condition_blocks_grandchild(self):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('a', 'NS', 'ns.a'),
        ])
        za = zone('a.example.test.', apex('ns') + [
            rec('x', 'NS', 'boot.x'),
            rec('boot.x', 'A', '192.0.2.7'),
        ])
        zx = zone('x.a.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.8')])
        result = analyze({'zones': [root, za, zx], 'roots': ['example.test.']})
        zx_entry = entry(result, 'x.a.example.test.')
        self.assertEqual(zx_entry['parent'], 'a.example.test.')
        glue = candidate(zx_entry, 'boot.x.a.example.test.')
        self.assertEqual(glue['addresses'], ['192.0.2.7'])
        self.assertEqual(glue['waiting_on'], ['a.example.test.'])
        self.assertEqual(glue['reason'], 'waiting')
        self.assertFalse(glue['ready'])
        self.assertIsNone(zx_entry['round'])
        self.assertFalse(result['all_reachable'])


class SourceIsolationTests(unittest.TestCase):
    def build(self):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('a', 'NS', 'ns.other'),
            rec('other', 'NS', 'ns.other'),
            rec('ns.other', 'A', '10.0.0.1'),
        ])
        zother = zone('other.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.1')])
        za = zone('a.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.2')])
        return {'zones': [root, zother, za], 'roots': ['example.test.']}

    def test_authoritative_source_wins_over_parent_copy(self):
        result = analyze(self.build())
        zother = entry(result, 'other.example.test.')
        self.assertEqual(zother['round'], 1)
        self.assertEqual(zother['witness']['channel'], 'glue')
        self.assertEqual(zother['witness']['address'], '10.0.0.1')
        za = entry(result, 'a.example.test.')
        cand = candidate(za, 'ns.other.example.test.')
        self.assertEqual(cand['channel'], 'authority')
        self.assertEqual(cand['address_zone'], 'other.example.test.')
        self.assertEqual(cand['addresses'], ['192.0.2.1'])
        self.assertEqual(za['round'], 2)
        self.assertEqual(za['witness']['address'], '192.0.2.1')
        self.assertEqual(za['witness']['address_zone'], 'other.example.test.')


class EarliestProofTests(unittest.TestCase):
    def test_earliest_proof_beats_lexicographically_smaller_ns(self):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('c', 'NS', 'a-ns.other'),
            rec('c', 'NS', 'z-boot.c'),
            rec('z-boot.c', 'A', '192.0.2.8'),
            rec('other', 'NS', 'ns.other'),
            rec('ns.other', 'A', '192.0.2.9'),
        ])
        zother = zone('other.example.test.', apex('ns') + [
            rec('ns', 'A', '192.0.2.9'),
            rec('a-ns', 'A', '192.0.2.10'),
        ])
        zc = zone('c.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.12')])
        result = analyze({'zones': [root, zother, zc], 'roots': ['example.test.']})
        zc_entry = entry(result, 'c.example.test.')
        self.assertEqual(zc_entry['round'], 1)
        # a-ns.other.example.test. sorts before z-boot.c.example.test. but its
        # proof needs other.example.test. (round 1), so it lands at round 2.
        self.assertEqual(zc_entry['witness']['ns'], 'z-boot.c.example.test.')
        self.assertEqual(zc_entry['witness']['channel'], 'glue')
        late = candidate(zc_entry, 'a-ns.other.example.test.')
        self.assertEqual(late['addresses'], ['192.0.2.10'])
        self.assertTrue(late['ready'])

    def test_witness_tie_breaks_by_smallest_tuple(self):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('d', 'NS', 'n.d'),
            rec('d', 'NS', 'm.d'),
            rec('m.d', 'A', '192.0.2.20'),
            rec('m.d', 'AAAA', '2001:db8::1'),
            rec('n.d', 'A', '192.0.2.21'),
        ])
        zd = zone('d.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.22')])
        result = analyze({'zones': [root, zd], 'roots': ['example.test.']})
        zd_entry = entry(result, 'd.example.test.')
        self.assertEqual(zd_entry['round'], 1)
        self.assertEqual(zd_entry['witness'], {'ns': 'm.d.example.test.', 'channel': 'glue',
                                               'address_zone': 'example.test.', 'address': '192.0.2.20'})
        addresses = candidate(zd_entry, 'm.d.example.test.')['addresses']
        self.assertEqual(addresses, sorted(addresses))


class OcclusionTests(unittest.TestCase):
    def test_nested_occluded_ns_and_missing_snapshot_block_parent_data(self):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('sub', 'NS', 'ns.deep.sub'),
            rec('deep.sub', 'NS', 'ns.deep.sub'),
            rec('ns.deep.sub', 'A', '192.0.2.5'),
            rec('a', 'NS', 'ns.deep.sub'),
        ])
        za = zone('a.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.6')])
        result = analyze({'zones': [root, za], 'roots': ['example.test.']})
        za_entry = entry(result, 'a.example.test.')
        cand = candidate(za_entry, 'ns.deep.sub.example.test.')
        self.assertEqual(cand['channel'], 'authority')
        self.assertIsNone(cand['address_zone'])
        self.assertEqual(cand['addresses'], [])
        self.assertEqual(cand['reason'], 'authority_unknown')
        self.assertEqual(cand['waiting_on'], [])
        self.assertFalse(za_entry['reachable'])
        self.assertNotIn('192.0.2.5', str(za_entry['candidates']))

    def test_occluded_delegation_fails_parent_child_contract(self):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('sub', 'NS', 'ns.sub'),
            rec('ns.sub', 'A', '192.0.2.4'),
            rec('deep.sub', 'NS', 'ns.deep.sub'),
        ])
        zdeep = zone('deep.sub.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.5')])
        with self.assertRaisesRegex(ValueError, 'delegation'):
            analyze({'zones': [root, zdeep], 'roots': ['example.test.']})


class AddressFormTests(unittest.TestCase):
    def build(self, glue_record):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('child', 'NS', 'ns.child'),
            glue_record,
        ])
        child = zone('child.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.11')])
        return {'zones': [root, child], 'roots': ['example.test.']}

    def test_single_a_glue(self):
        result = analyze(self.build(rec('ns.child', 'A', '192.0.2.10')))
        child = entry(result, 'child.example.test.')
        self.assertEqual(child['round'], 1)
        self.assertEqual(child['witness']['address'], '192.0.2.10')

    def test_single_aaaa_glue_normalized(self):
        result = analyze(self.build(rec('ns.child', 'AAAA', '2001:0DB8:0000:0000:0000:0000:0000:0001')))
        child = entry(result, 'child.example.test.')
        self.assertEqual(child['round'], 1)
        self.assertEqual(child['witness']['address'], '2001:db8::1')

    def test_aaaa_only_authority_channel(self):
        root = zone('example.test.', apex('ns1') + [
            rec('ns1', 'A', '192.0.2.53'),
            rec('c', 'NS', 'ns.other'),
            rec('other', 'NS', 'ns.other'),
            rec('ns.other', 'A', '192.0.2.9'),
        ])
        zother = zone('other.example.test.', apex('ns') + [rec('ns', 'AAAA', '2001:db8::53')])
        zc = zone('c.example.test.', apex('ns') + [rec('ns', 'A', '192.0.2.12')])
        result = analyze({'zones': [root, zother, zc], 'roots': ['example.test.']})
        zc_entry = entry(result, 'c.example.test.')
        self.assertEqual(zc_entry['round'], 2)
        self.assertEqual(zc_entry['witness']['address'], '2001:db8::53')


class NormalizationTests(unittest.TestCase):
    def test_case_relative_and_ipv6_forms_do_not_change_result(self):
        canonical = cycle([rec('boot.a', 'A', '192.0.2.10'), rec('v6.a', 'AAAA', '2001:db8::1')])
        variant = {
            'zones': [
                zone('EXAMPLE.TEST.', [
                    rec('@', 'SOA', SOA), rec('@', 'NS', 'NS1'), rec('NS1', 'A', '192.0.2.53'),
                    rec('A', 'NS', 'NS.B'), rec('a', 'NS', 'Boot.A'), rec('B', 'NS', 'ns.a'),
                    rec('Boot.A.EXAMPLE.TEST.', 'A', '192.0.2.10'),
                    rec('V6.A', 'AAAA', '2001:0DB8:0:0:0:0:0:1'),
                ]),
                zone('A.Example.Test.', [
                    rec('@', 'SOA', SOA), rec('@', 'NS', 'NS'),
                    rec('NS', 'A', '192.0.2.1'), rec('Boot', 'A', '192.0.2.2'),
                ]),
                zone('B.EXAMPLE.TEST.', [
                    rec('@', 'SOA', SOA), rec('@', 'NS', 'Ns'), rec('ns', 'A', '192.0.2.3'),
                ]),
            ],
            'roots': ['Example.Test.'],
        }
        self.assertEqual(analyze(canonical), analyze(variant))

    def test_input_disorder_does_not_change_result(self):
        base = cycle([rec('boot.a', 'A', '192.0.2.10')])
        shuffled = {'roots': list(base['roots']),
                    'zones': [zone(z['origin'], list(reversed(z['records'])))
                              for z in reversed(base['zones'])]}
        self.assertEqual(analyze(base), analyze(shuffled))


class ContractRejectionTests(unittest.TestCase):
    def test_duplicate_zone_origin_after_normalization(self):
        zones = [zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53'), rec('a', 'NS', 'ns.a'), rec('ns.a', 'A', '192.0.2.1')]),
                 zone('a.example.test.', apex('ns')),
                 zone('A.EXAMPLE.TEST.', apex('ns'))]
        with self.assertRaisesRegex(ValueError, 'duplicate zone origin'):
            analyze({'zones': zones, 'roots': ['example.test.']})

    def test_duplicate_roots_after_normalization(self):
        with self.assertRaisesRegex(ValueError, 'duplicate root'):
            analyze({'zones': [zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53')])],
                     'roots': ['example.test.', 'EXAMPLE.TEST.']})

    def test_roots_must_cover_every_ancestorless_zone(self):
        zones = [zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53')]),
                 zone('other.test.', apex('ns') + [rec('ns', 'A', '192.0.2.1')])]
        with self.assertRaisesRegex(ValueError, 'roots'):
            analyze({'zones': zones, 'roots': ['example.test.']})

    def test_roots_must_not_list_descendant_zone(self):
        zones = [zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53'), rec('a', 'NS', 'ns.a'), rec('ns.a', 'A', '192.0.2.1')]),
                 zone('a.example.test.', apex('ns'))]
        with self.assertRaisesRegex(ValueError, 'roots'):
            analyze({'zones': zones, 'roots': ['example.test.', 'a.example.test.']})

    def test_missing_parent_delegation_rejected(self):
        zones = [zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53')]),
                 zone('a.example.test.', apex('ns'))]
        with self.assertRaisesRegex(ValueError, 'delegation'):
            analyze({'zones': zones, 'roots': ['example.test.']})

    def test_top_level_and_shape_rejections(self):
        good_zone = zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53')])
        bad_inputs = [
            {'roots': ['example.test.']},
            {'zones': [good_zone], 'roots': ['example.test.'], 'extra': 1},
            {'zones': [], 'roots': ['example.test.']},
            {'zones': [good_zone], 'roots': []},
            {'zones': [good_zone], 'roots': ['example.test']},
            {'zones': [good_zone], 'roots': ['@']},
            {'zones': [good_zone], 'roots': 'example.test.'},
            {'zones': [dict(good_zone, extra=1)], 'roots': ['example.test.']},
            {'zones': ['not-a-zone'], 'roots': ['example.test.']},
        ]
        for bad in bad_inputs:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    analyze(bad)

    def test_zone_count_bound(self):
        children = []
        root_records = apex('ns1') + [rec('ns1', 'A', '192.0.2.53')]
        for i in range(128):
            name = 'c%d' % i
            root_records.append(rec(name, 'NS', 'ns.%s' % name))
            root_records.append(rec('ns.%s' % name, 'A', '192.0.3.%d' % (i % 250 + 1)))
            children.append(zone('%s.example.test.' % name, apex('ns') + [rec('ns', 'A', '192.0.4.%d' % (i % 250 + 1))]))
        zones = [zone('example.test.', root_records)] + children
        with self.assertRaisesRegex(ValueError, 'bounded array'):
            analyze({'zones': zones, 'roots': ['example.test.']})
        self.assertTrue(analyze({'zones': zones[:-1], 'roots': ['example.test.']})['all_reachable'])

    def test_total_record_budget(self):
        filler = [rec('r%d' % i, 'A', '192.0.2.1') for i in range(9994)]
        root = zone('example.test.', apex('ns1') + [rec('ns1', 'A', '192.0.2.53'),
                                                   rec('child', 'NS', 'ns.child'),
                                                   rec('ns.child', 'A', '192.0.2.10')] + filler[:4994])
        child = zone('child.example.test.', apex('ns') + filler[4994:])
        self.assertEqual(len(root['records']) + len(child['records']), 10001)
        with self.assertRaisesRegex(ValueError, 'record budget'):
            analyze({'zones': [root, child], 'roots': ['example.test.']})
        root['records'] = root['records'][:-1]
        self.assertTrue(analyze({'zones': [root, child], 'roots': ['example.test.']})['all_reachable'])

    def test_inherited_single_zone_rejections(self):
        base = cycle()
        bad_type = cycle()
        bad_type['zones'][0]['records'].append(rec('x', 'SRV', '1 2 3 x'))
        bad_ip = cycle()
        bad_ip['zones'][1]['records'][2]['data'] = '192.0.2.999'
        duplicate = cycle()
        duplicate['zones'][0]['records'].append(dict(duplicate['zones'][0]['records'][1]))
        for bad in (bad_type, bad_ip, duplicate):
            with self.subTest():
                with self.assertRaises(ValueError):
                    analyze(bad)
        self.assertTrue(analyze(base) is not None)


if __name__ == '__main__':
    unittest.main()
