import json
import unittest

from dns_zone_audit.cache_replay import analyze

B = 'b.example.test.'
A = 'a.example.test.'
C = 'c.example.test.'


def ev(seq, at, name, kind, **fields):
    return {'seq': seq, 'at': at, 'name': name, 'kind': kind, **fields}


def rrset(seq, at, name, qtype='A', ttl=60, addresses=('192.0.2.10',)):
    return ev(seq, at, name, 'rrset', qtype=qtype, ttl=ttl, addresses=list(addresses))


def alias(seq, at, name, target, ttl=60):
    return ev(seq, at, name, 'alias', ttl=ttl, target=target)


def probe(seq, at, name, qtype='A'):
    return ev(seq, at, name, 'probe', qtype=qtype)


def outcomes(data):
    return [p['status'] for p in analyze({'events': data})['probes']]


class AcceptanceLinkageTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            rrset(1, 0, B, 'A', 60, ['192.0.2.10']),
            rrset(2, 0, B, 'AAAA', 60, ['2001:db8::10']),
            alias(3, 0, A, B, 60),
            probe(4, 1, A, 'A'),
            ev(5, 2, B, 'nxdomain', ttl=3),
            probe(6, 2, A, 'A'),
            probe(7, 5, A, 'AAAA'),
            alias(8, 5, B, C, 20),
            probe(9, 5, A, 'A'),
            rrset(10, 5, C, 'A', 10, ['192.0.2.20']),
            probe(11, 5, A, 'A'),
        ]

    def test_first_probe_hits_alias_then_rrset(self):
        p = analyze({'events': self.events})['probes'][0]
        self.assertEqual((p['seq'], p['at'], p['status'], p['terminal_name']),
                         (4, 1, 'hit', B))
        self.assertEqual(p['addresses'], ['192.0.2.10'])
        self.assertEqual(p['evidence'], [3, 1])
        self.assertEqual(p['expires_at'], 60)

    def test_short_nxdomain_hides_old_address_without_erasing_it(self):
        nx, expired = analyze({'events': self.events})['probes'][1:3]
        self.assertEqual(nx['status'], 'nxdomain')
        self.assertEqual(nx['terminal_name'], B)
        self.assertEqual(nx['evidence'], [3, 5])
        self.assertEqual(nx['expires_at'], 5)
        self.assertEqual(nx['addresses'], [])
        # Same second, after the NXDOMAIN expires (at 5 is >= 2 + 3): the
        # old AAAA must be gone even though its own TTL runs to 60.
        self.assertEqual(expired['status'], 'miss')
        self.assertEqual(expired['terminal_name'], B)
        self.assertEqual(expired['evidence'], [3])
        self.assertIsNone(expired['expires_at'])

    def test_same_second_order_is_seq_order(self):
        before, after = analyze({'events': self.events})['probes'][3:5]
        self.assertEqual(before['status'], 'miss')
        self.assertEqual(before['terminal_name'], C)
        self.assertEqual(before['evidence'], [3, 8])
        self.assertIsNone(before['expires_at'])
        self.assertEqual(after['status'], 'hit')
        self.assertEqual(after['terminal_name'], C)
        self.assertEqual(after['addresses'], ['192.0.2.20'])
        self.assertEqual(after['evidence'], [3, 8, 10])
        self.assertEqual(after['expires_at'], 15)

    def test_fixture_reproduces_linkage_sample(self):
        from pathlib import Path
        data = json.loads((Path(__file__).resolve().parents[1]
                           / 'fixtures/cache-replay-input.json').read_text())
        self.assertEqual(outcomes(data['events']),
                         ['hit', 'nxdomain', 'miss', 'miss', 'hit'])


class CacheSemanticsTests(unittest.TestCase):
    def test_zero_ttl_overrides_and_leaves_no_readable_fact(self):
        events = [rrset(1, 0, B, 'A', 60), ev(2, 1, B, 'nxdomain', ttl=0),
                  probe(3, 1, B), probe(4, 1, B, 'AAAA')]
        result = analyze({'events': events})['probes']
        self.assertEqual(result[0]['status'], 'miss')
        self.assertEqual(result[0]['evidence'], [])
        self.assertEqual(result[1]['status'], 'miss')
        self.assertEqual(result[1]['evidence'], [])

    def test_zero_ttl_rrset_clears_previous_rrset(self):
        events = [rrset(1, 0, B, 'A', 60), rrset(2, 1, B, 'A', 0, ['192.0.2.99']),
                  probe(3, 1, B)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'miss')
        self.assertEqual(result['evidence'], [])

    def test_nodata_does_not_affect_sibling_type(self):
        events = [rrset(1, 0, B, 'A', 60), ev(2, 0, B, 'nodata', qtype='AAAA', ttl=60),
                  probe(3, 0, B, 'A'), probe(4, 0, B, 'AAAA')]
        a, aaaa = analyze({'events': events})['probes']
        self.assertEqual(a['status'], 'hit')
        self.assertEqual(a['addresses'], ['192.0.2.10'])
        self.assertEqual(aaaa['status'], 'nodata')
        self.assertEqual(aaaa['evidence'], [2])

    def test_rrset_replaces_whole_rrset_not_append(self):
        events = [rrset(1, 0, B, 'A', 60, ['192.0.2.10', '192.0.2.11']),
                  rrset(2, 1, B, 'A', 60, ['192.0.2.99']), probe(3, 1, B)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['addresses'], ['192.0.2.99'])
        self.assertEqual(result['evidence'], [2])

    def test_nodata_replaces_rrset_of_same_type(self):
        events = [rrset(1, 0, B, 'A', 60), ev(2, 1, B, 'nodata', qtype='A', ttl=60),
                  probe(3, 1, B, 'A')]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'nodata')
        self.assertEqual(result['evidence'], [2])

    def test_alias_replaces_all_facts_for_name(self):
        events = [rrset(1, 0, B, 'A', 60), ev(2, 0, B, 'nxdomain', ttl=60),
                  alias(3, 0, B, C, 60), probe(4, 0, B)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'miss')
        self.assertEqual(result['terminal_name'], C)
        self.assertEqual(result['evidence'], [3])

    def test_nxdomain_is_exact_name_only(self):
        child = 'x.b.example.test.'
        events = [rrset(1, 0, child, 'A', 60), ev(2, 0, B, 'nxdomain', ttl=60),
                  probe(3, 0, child)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'hit')
        self.assertEqual(result['terminal_name'], child)

    def test_alias_expires_before_terminal(self):
        events = [alias(1, 0, A, B, ttl=2), rrset(2, 0, B, 'A', 60),
                  probe(3, 1, A), probe(4, 2, A)]
        live, expired = analyze({'events': events})['probes']
        self.assertEqual(expired['status'], 'miss')
        self.assertEqual(expired['terminal_name'], A)
        self.assertEqual(expired['evidence'], [])
        self.assertEqual(live['status'], 'hit')
        # The alias TTL bounds the known result below the terminal's 60.
        self.assertEqual(live['expires_at'], 2)

    def test_terminal_expiry_is_exclusive(self):
        events = [alias(1, 0, A, B, ttl=10), rrset(2, 0, B, 'A', 3),
                  probe(3, 3, A, 'A')]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'miss')
        self.assertEqual(result['terminal_name'], B)

    def test_miss_keeps_only_aliases_already_taken(self):
        events = [alias(1, 0, A, B), alias(2, 0, B, C), probe(3, 0, A)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'miss')
        self.assertEqual(result['terminal_name'], C)
        self.assertEqual(result['evidence'], [1, 2])
        self.assertIsNone(result['expires_at'])

    def test_probe_does_not_write_back_or_refresh(self):
        events = [alias(1, 0, A, B), rrset(2, 0, B, 'A', 10),
                  probe(3, 0, A), probe(4, 5, A), probe(5, 10, A)]
        first, second, third = analyze({'events': events})['probes']
        self.assertEqual(first['expires_at'], 10)
        # Re-probing did not refresh the cached TTL.
        self.assertEqual(second['expires_at'], 10)
        self.assertEqual(third['status'], 'miss')


class LoopTests(unittest.TestCase):
    def test_two_name_loop_reports_first_repeat(self):
        events = [alias(1, 0, A, B), alias(2, 0, B, A), probe(3, 0, A)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'loop')
        self.assertEqual(result['terminal_name'], A)
        self.assertEqual(result['evidence'], [1, 2])
        self.assertIsNone(result['expires_at'])
        self.assertEqual(result['addresses'], [])

    def test_self_loop_includes_repeating_alias(self):
        events = [alias(1, 0, A, A), probe(2, 0, A)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'loop')
        self.assertEqual(result['terminal_name'], A)
        self.assertEqual(result['evidence'], [1])

    def test_loop_terminal_name_is_first_repeated_name(self):
        events = [alias(1, 0, A, B), alias(2, 0, B, C), alias(3, 0, C, B), probe(4, 0, A)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['terminal_name'], B)
        self.assertEqual(result['evidence'], [1, 2, 3])

    def test_expired_alias_breaks_loop_into_miss(self):
        events = [alias(1, 0, A, B, ttl=1), alias(2, 0, B, A, ttl=60), probe(3, 1, A)]
        result = analyze({'events': events})['probes'][0]
        self.assertEqual(result['status'], 'miss')
        self.assertEqual(result['terminal_name'], A)


class OrderingTests(unittest.TestCase):
    def test_array_order_is_ignored(self):
        events = [rrset(1, 0, B, 'A', 60), alias(2, 0, A, B, 60), probe(3, 1, A)]
        shuffled = [events[2], events[0], events[1]]
        self.assertEqual(analyze({'events': events}), analyze({'events': shuffled}))

    def test_same_second_probe_before_update_cannot_see_it(self):
        events = [alias(1, 0, A, B), probe(2, 0, A), rrset(3, 0, B, 'A', 60)]
        before, = analyze({'events': events})['probes']
        self.assertEqual(before['status'], 'miss')
        self.assertEqual(before['evidence'], [1])

    def test_earlier_probe_not_rewritten_by_later_observation(self):
        events = [probe(1, 0, B), rrset(2, 0, B, 'A', 60), probe(3, 0, B)]
        first, second = analyze({'events': events})['probes']
        self.assertEqual(first['status'], 'miss')
        self.assertEqual(second['status'], 'hit')

    def test_probe_results_sorted_by_seq(self):
        events = [probe(50, 2, B), probe(10, 1, B), alias(1, 0, A, B)]
        seqs = [p['seq'] for p in analyze({'events': events})['probes']]
        self.assertEqual(seqs, [10, 50])

    def test_ttl_zero_observation_is_an_ordering_barrier(self):
        events = [rrset(1, 0, B, 'A', 60), probe(2, 0, B),
                  ev(3, 0, B, 'nxdomain', ttl=0), probe(4, 0, B)]
        hit, after = analyze({'events': events})['probes']
        self.assertEqual(hit['status'], 'hit')
        self.assertEqual(after['status'], 'miss')


class ValidationTests(unittest.TestCase):
    def assertRejected(self, data, pattern=None):
        with self.assertRaises(ValueError) as caught:
            analyze(data)
        if pattern:
            self.assertRegex(str(caught.exception), pattern)

    def test_valid_minimal_log(self):
        self.assertEqual(analyze({'events': [probe(1, 0, B)]}),
                         {'probes': [{'seq': 1, 'at': 0, 'name': B, 'qtype': 'A',
                                      'status': 'miss', 'terminal_name': B,
                                      'addresses': [], 'evidence': [],
                                      'expires_at': None}]})

    def test_top_level_must_be_exactly_events(self):
        self.assertRejected({})
        self.assertRejected({'events': [], 'extra': 1})
        self.assertRejected({'events': [probe(1, 0, B)], 'other': []})

    def test_event_count_bounds(self):
        self.assertRejected({'events': []}, '10000')
        self.assertRejected({'events': [probe(i, 0, B) for i in range(1, 10002)]})
        many = [probe(i, 0, B) for i in range(1, 10001)]
        self.assertTrue(analyze({'events': many})['probes'])

    def test_at_least_one_probe(self):
        self.assertRejected({'events': [rrset(1, 0, B)]}, 'probe')

    def test_seq_must_be_unique_positive_integer(self):
        self.assertRejected({'events': [probe(1, 0, B), probe(1, 0, B)]}, 'seq')
        self.assertRejected({'events': [probe(0, 0, B)]})
        self.assertRejected({'events': [probe(True, 0, B)]})
        self.assertRejected({'events': [probe(-1, 0, B)]})

    def test_at_is_nonnegative_and_nonretreating_in_seq_order(self):
        self.assertRejected({'events': [probe(1, -1, B)]})
        self.assertRejected({'events': [probe(1, True, B)]})
        self.assertRejected({'events': [probe(1, 5, B), probe(2, 4, B)]}, 'retreat')
        self.assertEqual([p['at'] for p in analyze({'events': [
            probe(2, 5, B), probe(1, 5, B)]})['probes']], [5, 5])

    def test_kind_specific_fields_are_exclusive(self):
        self.assertRejected({'events': [ev(1, 0, B, 'rrset', ttl=1,
                                           addresses=['192.0.2.1'])]})
        self.assertRejected({'events': [ev(1, 0, B, 'probe', qtype='A', ttl=5)]})
        self.assertRejected({'events': [ev(1, 0, B, 'nxdomain', ttl=5, qtype='A')]})
        self.assertRejected({'events': [ev(1, 0, B, 'unknown')]})

    def test_qtype_restricted(self):
        self.assertRejected({'events': [probe(1, 0, B, 'MX')]})
        self.assertRejected({'events': [ev(1, 0, B, 'nodata', qtype='CNAME', ttl=5)]})

    def test_ttl_bounds_and_bool_rejected(self):
        self.assertRejected({'events': [ev(1, 0, B, 'nxdomain', ttl=-1)]})
        self.assertRejected({'events': [ev(1, 0, B, 'nxdomain', ttl=2147483648)]})
        self.assertRejected({'events': [ev(1, 0, B, 'nxdomain', ttl=True)]})
        self.assertEqual(analyze({'events': [ev(1, 0, B, 'nxdomain', ttl=2147483647), probe(2, 0, B)]})
                         ['probes'][0]['expires_at'], 2147483647)

    def test_names_must_be_absolute_nonroot_and_wildcard_free(self):
        for bad in ('b', '@', '.', '*', '*.example.test.', 'B..', 'a b.test.',
                    'x.%eth.test.', '*.b.example.test.'):
            with self.subTest(name=bad):
                self.assertRejected({'events': [probe(1, 0, bad)]})
        self.assertRejected({'events': [alias(1, 0, A, 'b')]})
        self.assertRejected({'events': [alias(1, 0, A, '*')]})

    def test_names_normalize_to_lowercase_absolute(self):
        result = analyze({'events': [probe(1, 0, 'B.EXAMPLE.TEST.')]})['probes'][0]
        self.assertEqual(result['name'], B)

    def test_addresses_required_valid_and_normalized(self):
        self.assertRejected({'events': [rrset(1, 0, B, 'A', 60, [])]}, 'addresses')
        self.assertRejected({'events': [rrset(1, 0, B, 'A', 60, ['192.0.2.999'])]})
        self.assertRejected({'events': [rrset(1, 0, B, 'A', 60, ['2001:db8::1'])]})
        self.assertRejected({'events': [rrset(1, 0, B, 'AAAA', 60, ['192.0.2.1'])]})
        self.assertRejected({'events': [rrset(1, 0, B, 'AAAA', 60, ['fe80::1%eth0'])]})
        self.assertRejected({'events': [rrset(1, 0, B, 'A', 60, ['192.0.2.1', '192.0.2.1'])]})
        result = analyze({'events': [rrset(1, 0, B, 'AAAA', 60,
                                           ['2001:0db8::2', '2001:DB8::1']), probe(2, 0, B, 'AAAA')]})
        self.assertEqual(result['probes'][0]['addresses'], ['2001:db8::1', '2001:db8::2'])

    def test_addresses_must_be_array_of_strings(self):
        self.assertRejected({'events': [rrset(1, 0, B, 'A', 60, '192.0.2.1')]})
        self.assertRejected({'events': [rrset(1, 0, B, 'A', 60, [192])]})


if __name__ == '__main__':
    unittest.main()
