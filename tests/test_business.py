import json
import unittest
from pathlib import Path
from dns_zone_audit.model import analyze, dns_name

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    return json.loads((ROOT / 'fixtures/input.json').read_text())


class DnsZoneTests(unittest.TestCase):
    def test_delegation_finding(self):
        report = analyze(fixture())
        self.assertFalse(report['valid'])
        self.assertEqual(report['issues'][0]['code'], 'in_zone_glue_missing')

    def test_valid_zone(self):
        data = fixture()
        data['records'] = data['records'][:5]
        report = analyze(data)
        self.assertTrue(report['valid'])
        self.assertEqual(report['record_count'], 5)

    def test_cname_exclusivity(self):
        data = fixture()
        data['records'].append({'owner': 'www', 'type': 'A', 'ttl': None, 'data': '192.0.2.9'})
        self.assertIn('cname_exclusive_conflict', {x['code'] for x in analyze(data)['issues']})

    def test_mx_alias_target(self):
        data = fixture()
        data['records'].append({'owner': '@', 'type': 'MX', 'ttl': None, 'data': {'preference': 10, 'exchange': 'www'}})
        self.assertIn('mx_target_is_alias', {x['code'] for x in analyze(data)['issues']})

    def test_duplicate_record_rejected(self):
        data = fixture()
        data['records'].append(data['records'][1])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            analyze(data)

    def test_bad_ipv4_rejected(self):
        data = fixture()
        data['records'][2]['data'] = '192.0.2.999'
        with self.assertRaises(ValueError):
            analyze(data)

    def test_unknown_type_rejected(self):
        data = fixture()
        data['records'].append({'owner': 'x', 'type': 'SRV', 'ttl': None, 'data': 'x'})
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            analyze(data)

    def test_relative_and_apex_names(self):
        self.assertEqual(dns_name('@', 'example.test.'), 'example.test.')
        self.assertEqual(dns_name('NS1', 'example.test.'), 'ns1.example.test.')
        self.assertEqual(dns_name('ns1.other.test.', 'example.test.'), 'ns1.other.test.')

    def test_apex_soa_and_ns_requirements(self):
        data = fixture()
        data['records'] = [r for r in data['records'] if not (r['owner'] == '@' and r['type'] == 'SOA')]
        self.assertIn('apex_soa_count', {x['code'] for x in analyze(data)['issues']})

    def test_aaaa_normalization(self):
        data = fixture()
        data['records'].append({'owner': 'v6', 'type': 'AAAA', 'ttl': None, 'data': '2001:0db8::1'})
        result = next(r for r in analyze(data)['records'] if r['type'] == 'AAAA')
        self.assertEqual(result['data'], '2001:db8::1')

    def test_glue_requires_address_record(self):
        data = fixture()
        data['records'].append({'owner': 'ns.child', 'type': 'TXT', 'ttl': None, 'data': 'not glue'})
        self.assertIn('in_zone_glue_missing', {x['code'] for x in analyze(data)['issues']})
        data['records'].append({'owner': 'ns.child', 'type': 'AAAA', 'ttl': None, 'data': '2001:db8::53'})
        self.assertTrue(analyze(data)['valid'])

    def test_external_target_suffix_is_not_in_zone(self):
        data = fixture()
        data['records'][-1]['data'] = 'ns.notexample.test.'
        self.assertTrue(analyze(data)['valid'])

    def test_record_owner_outside_zone_rejected(self):
        data = fixture()
        data['records'][2]['owner'] = 'ns.other.test.'
        with self.assertRaisesRegex(ValueError, 'outside zone'):
            analyze(data)
