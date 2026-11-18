import copy
import json
import unittest
from pathlib import Path

from dns_zone_audit.change import analyze

ROOT = Path(__file__).resolve().parents[1]


def zone(serial=7, records=None):
    data = json.loads((ROOT / 'fixtures/input.json').read_text())
    data['records'][0]['data']['serial'] = serial
    if records is not None:
        data['records'] = records
    return data


def pair(current=None, candidate=None):
    return {'current': zone() if current is None else current,
            'candidate': zone() if candidate is None else candidate}


class SerialTests(unittest.TestCase):
    def test_same_serial_and_records(self):
        result = analyze(pair())
        self.assertEqual(result['serial'], {'current': 7, 'candidate': 7, 'delta': 0, 'relation': 'same'})
        self.assertFalse(result['can_publish'])
        self.assertEqual(result['summary'], {'added': 0, 'removed': 0, 'ttl_changed': 0, 'unchanged': 6})

    def test_same_serial_with_record_change_is_not_publishable(self):
        candidate = zone()
        candidate['records'].append({'owner': 'new', 'type': 'A', 'ttl': None, 'data': '192.0.2.9'})
        result = analyze(pair(candidate=candidate))
        self.assertEqual(result['serial']['relation'], 'same')
        self.assertFalse(result['can_publish'])
        self.assertEqual(result['summary']['added'], 1)

    def test_ordinary_increment(self):
        result = analyze(pair(zone(10), zone(11)))
        self.assertEqual(result['serial']['delta'], 1)
        self.assertEqual(result['serial']['relation'], 'newer')
        self.assertTrue(result['can_publish'])

    def test_wrap_forward_is_newer(self):
        result = analyze(pair(zone(0xffffffff), zone(0)))
        self.assertEqual(result['serial']['delta'], 1)
        self.assertEqual(result['serial']['relation'], 'newer')
        self.assertTrue(result['can_publish'])

    def test_half_space_is_ambiguous_both_directions(self):
        forward = analyze(pair(zone(0), zone(2 ** 31)))
        self.assertEqual(forward['serial']['delta'], 2 ** 31)
        self.assertEqual(forward['serial']['relation'], 'ambiguous')
        self.assertFalse(forward['can_publish'])
        backward = analyze(pair(zone(2 ** 31), zone(0)))
        self.assertEqual(backward['serial']['delta'], 2 ** 31)
        self.assertEqual(backward['serial']['relation'], 'ambiguous')
        self.assertFalse(backward['can_publish'])

    def test_half_space_neighbours(self):
        newest = analyze(pair(zone(0), zone(2 ** 31 - 1)))
        self.assertEqual(newest['serial']['relation'], 'newer')
        self.assertTrue(newest['can_publish'])
        oldest = analyze(pair(zone(0), zone(2 ** 31 + 1)))
        self.assertEqual(oldest['serial']['delta'], 2 ** 31 + 1)
        self.assertEqual(oldest['serial']['relation'], 'older')
        self.assertFalse(oldest['can_publish'])

    def test_older_candidate_is_not_publishable(self):
        result = analyze(pair(zone(11), zone(10)))
        self.assertEqual(result['serial']['delta'], 2 ** 32 - 1)
        self.assertEqual(result['serial']['relation'], 'older')
        self.assertFalse(result['can_publish'])

    def test_wrap_below_current_is_older(self):
        result = analyze(pair(zone(0), zone(0xffffffff)))
        self.assertEqual(result['serial']['relation'], 'older')
        self.assertFalse(result['can_publish'])

    def test_candidate_changes_do_not_override_older_serial(self):
        candidate = zone(9)
        candidate['records'].append({'owner': 'new', 'type': 'A', 'ttl': None, 'data': '192.0.2.9'})
        candidate['records'] = [r for r in candidate['records'] if not (r['owner'] == 'child')]
        result = analyze(pair(zone(10), candidate))
        self.assertEqual(result['serial']['relation'], 'older')
        self.assertFalse(result['can_publish'])
        # The new/removed data is reported, plus the serial-bearing SOA pair.
        self.assertEqual(result['summary'], {'added': 2, 'removed': 2, 'ttl_changed': 0, 'unchanged': 4})

    def test_ambiguous_candidate_is_not_publishable(self):
        candidate = zone(10 + 2 ** 31)
        candidate['records'].append({'owner': 'new', 'type': 'A', 'ttl': None, 'data': '192.0.2.9'})
        result = analyze(pair(zone(10), candidate))
        self.assertEqual(result['serial']['relation'], 'ambiguous')
        self.assertFalse(result['can_publish'])


class ChangeTests(unittest.TestCase):
    def test_ttl_only_change(self):
        candidate = zone(8)
        candidate['records'][3]['ttl'] = 120
        result = analyze(pair(zone(7), candidate))
        self.assertTrue(result['can_publish'])
        changed = [c for c in result['changes'] if c['change'] == 'ttl_changed']
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]['identity']['owner'], 'www.example.test.')
        self.assertEqual(changed[0]['before']['ttl'], 3600)
        self.assertEqual(changed[0]['after']['ttl'], 120)
        self.assertEqual(changed[0]['before']['data'], changed[0]['after']['data'])
        # The serial-bearing SOA RDATA also differs, so it is removed plus added.
        self.assertEqual(result['summary'], {'added': 1, 'removed': 1, 'ttl_changed': 1, 'unchanged': 4})

    def test_explicit_ttl_equal_to_inherited_default_is_unchanged(self):
        candidate = zone()
        candidate['records'][1]['ttl'] = 3600
        result = analyze(pair(candidate=candidate))
        ns = next(c for c in result['changes']
                  if c['identity']['type'] == 'NS' and c['identity']['owner'] == 'example.test.')
        self.assertEqual(ns['before']['ttl'], ns['after']['ttl'])
        self.assertEqual(ns['change'], 'unchanged')
        self.assertNotIn('ttl_changed', {c['change'] for c in result['changes']})

    def test_rdata_change_is_removed_plus_added(self):
        candidate = zone(8)
        candidate['records'][4]['data'] = '192.0.2.81'
        result = analyze(pair(zone(7), candidate))
        related = [c for c in result['changes'] if c['identity']['type'] == 'A'
                   and c['identity']['data'] in ('192.0.2.80', '192.0.2.81')
                   and c['identity']['owner'] == 'web.example.test.']
        self.assertEqual([c['change'] for c in related], ['removed', 'added'])
        self.assertEqual(len(related), 2)
        self.assertEqual(related[0]['before']['data'], '192.0.2.80')
        self.assertIsNone(related[1]['before'])
        self.assertEqual(related[1]['after']['data'], '192.0.2.81')

    def test_normalization_equates_owner_case_absolute_and_ipv6(self):
        current = zone()
        candidate = copy.deepcopy(current)
        candidate['records'][2]['owner'] = 'NS1.example.test.'
        candidate['records'][4]['owner'] = 'WEB.Example.Test.'
        candidate['records'].append({'owner': 'v6', 'type': 'AAAA', 'ttl': None,
                                     'data': '2001:0db8:0000:0000:0000:0000:0000:0053'})
        current['records'].append({'owner': 'V6', 'type': 'AAAA', 'ttl': None,
                                   'data': '2001:db8::53'})
        result = analyze({'current': current, 'candidate': candidate})
        self.assertEqual(result['summary'], {'added': 0, 'removed': 0, 'ttl_changed': 0, 'unchanged': 7})
        self.assertTrue(all(c['identity']['owner'] == c['identity']['owner'].lower() for c in result['changes']))
        v6 = next(c for c in result['changes'] if c['identity']['type'] == 'AAAA')
        self.assertEqual(v6['identity']['data'], '2001:db8::53')

    def test_relative_and_absolute_shared_identity(self):
        current = zone()
        candidate = zone()
        current['records'].append({'owner': 'alias.example.test.', 'type': 'CNAME', 'ttl': None, 'data': 'web.example.test.'})
        candidate['records'].append({'owner': 'alias', 'type': 'CNAME', 'ttl': None, 'data': 'WEB'})
        result = analyze({'current': current, 'candidate': candidate})
        self.assertEqual(result['summary'], {'added': 0, 'removed': 0, 'ttl_changed': 0, 'unchanged': 7})

    def test_default_ttl_change_reports_inherited_ttl_changes(self):
        candidate = zone()
        candidate['default_ttl'] = 7200
        result = analyze(pair(candidate=candidate))
        ttl_changed = [c for c in result['changes'] if c['change'] == 'ttl_changed']
        self.assertEqual(len(ttl_changed), 4)
        self.assertTrue(all(c['before']['ttl'] == 3600 and c['after']['ttl'] == 7200 for c in ttl_changed))
        explicit = next(c for c in result['changes'] if c['identity']['owner'] == 'web.example.test.')
        self.assertEqual(explicit['change'], 'unchanged')

    def test_txt_payload_is_preserved_verbatim(self):
        current = zone()
        candidate = zone()
        current['records'].append({'owner': 't', 'type': 'TXT', 'ttl': None, 'data': 'Hello, World!'})
        candidate['records'].append({'owner': 'T.Example.Test.', 'type': 'TXT', 'ttl': None, 'data': 'Hello, World!'})
        result = analyze({'current': current, 'candidate': candidate})
        txt = next(c for c in result['changes'] if c['identity']['type'] == 'TXT')
        self.assertEqual(txt['change'], 'unchanged')
        self.assertEqual(txt['identity']['data'], 'Hello, World!')

    def test_record_input_order_does_not_matter(self):
        current = zone(7)
        candidate = zone(7)
        candidate['records'].reverse()
        candidate['records'][0]['ttl'] = 42
        forward = analyze({'current': current, 'candidate': candidate})
        candidate['records'].reverse()
        backward = analyze({'current': current, 'candidate': candidate})
        self.assertEqual(forward, backward)

    def test_changes_have_stable_shape_and_order(self):
        candidate = zone(8)
        candidate['records'].append({'owner': 'a', 'type': 'A', 'ttl': 10, 'data': '192.0.2.1'})
        candidate['records'][4]['ttl'] = 30
        candidate['records'] = [r for r in candidate['records'] if not (r['owner'] == 'child')]
        result = analyze(pair(zone(7), candidate))
        keys = [(c['identity']['owner'], c['identity']['type'],
                 json.dumps(c['identity']['data'], sort_keys=True))
                for c in result['changes']]
        self.assertEqual(keys, sorted(keys))
        for change in result['changes']:
            self.assertEqual(set(change), {'change', 'identity', 'before', 'after'})
            self.assertEqual(set(change['identity']), {'owner', 'type', 'data'})
            for side in (change['before'], change['after']):
                if side is not None:
                    self.assertEqual(set(side), {'ttl', 'data'})
        self.assertEqual(sum(result['summary'].values()), len(result['changes']))

    def test_added_and_removed_records(self):
        candidate = zone(9)
        candidate['records'] = [r for r in candidate['records'] if r['owner'] != 'child']
        candidate['records'].append({'owner': 'brand-new', 'type': 'TXT', 'ttl': None, 'data': 'hello'})
        result = analyze(pair(zone(8), candidate))
        self.assertEqual(result['summary'], {'added': 2, 'removed': 2, 'ttl_changed': 0, 'unchanged': 4})
        added = next(c for c in result['changes'] if c['change'] == 'added' and c['identity']['type'] == 'TXT')
        removed = next(c for c in result['changes'] if c['change'] == 'removed')
        self.assertEqual(added['identity']['data'], 'hello')
        self.assertIsNone(added['before'])
        self.assertEqual(removed['identity']['type'], 'NS')
        self.assertIsNone(removed['after'])

    def test_duplicate_records_rejected(self):
        candidate = zone()
        candidate['records'].append({'owner': 'www', 'type': 'CNAME', 'ttl': None, 'data': 'web'})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            analyze({'current': zone(), 'candidate': candidate})

    def test_duplicate_identity_with_different_ttl_rejected(self):
        candidate = zone()
        candidate['records'].append({'owner': 'www', 'type': 'CNAME', 'ttl': 60, 'data': 'web'})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            analyze({'current': zone(), 'candidate': candidate})


class ContractTests(unittest.TestCase):
    def test_top_level_fields_strict(self):
        with self.assertRaises(ValueError):
            analyze({'current': zone()})
        with self.assertRaises(ValueError):
            analyze({'current': zone(), 'candidate': zone(), 'extra': 1})
        with self.assertRaises(ValueError):
            analyze({'current': zone(), 'candidate': zone(), 'origin': 'x'})

    def test_different_origins_rejected(self):
        candidate = zone()
        candidate['origin'] = 'other.test.'
        with self.assertRaisesRegex(ValueError, 'origin'):
            analyze(pair(candidate=candidate))

    def test_missing_apex_soa_rejected(self):
        candidate = zone()
        candidate['records'] = [r for r in candidate['records'] if r['type'] != 'SOA']
        with self.assertRaisesRegex(ValueError, 'apex SOA'):
            analyze(pair(candidate=candidate))

    def test_duplicate_apex_soa_rejected(self):
        candidate = zone()
        second = copy.deepcopy(candidate['records'][0])
        second['data']['serial'] = 99
        candidate['records'].append(second)
        with self.assertRaisesRegex(ValueError, 'apex SOA'):
            analyze(pair(candidate=candidate))

    def test_non_apex_soa_does_not_satisfy_requirement(self):
        candidate = zone()
        soa = candidate['records'][0]
        candidate['records'] = [r for r in candidate['records'] if r is not soa]
        moved = copy.deepcopy(soa)
        moved['owner'] = 'child'
        candidate['records'].append(moved)
        with self.assertRaisesRegex(ValueError, 'apex SOA'):
            analyze(pair(candidate=candidate))

    def test_serial_bounds_and_type(self):
        for bad in (-1, 2 ** 32, True, 1.5, '7', None):
            with self.subTest(bad=bad):
                candidate = zone()
                candidate['records'][0]['data']['serial'] = bad
                with self.assertRaises(ValueError):
                    analyze(pair(candidate=candidate))

    def test_record_fields_strict(self):
        candidate = zone()
        candidate['records'][1]['extra'] = 1
        with self.assertRaises(ValueError):
            analyze(pair(candidate=candidate))
        with self.assertRaises(ValueError):
            analyze({'current': {'origin': 'example.test.'}, 'candidate': zone()})

    def test_result_has_no_paths_or_time(self):
        result = analyze(pair(zone(7), zone(8)))
        self.assertEqual(set(result), {'origin', 'serial', 'can_publish', 'changes', 'summary'})
        self.assertEqual(set(result['serial']), {'current', 'candidate', 'delta', 'relation'})
        self.assertEqual(set(result['summary']), {'added', 'removed', 'ttl_changed', 'unchanged'})
        text = json.dumps(result)
        self.assertNotIn(str(ROOT), text)
