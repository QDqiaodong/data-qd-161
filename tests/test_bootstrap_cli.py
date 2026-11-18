import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'dns_zone_audit.bootstrap_cli'

SOA = {'mname': 'ns1', 'rname': 'hostmaster', 'serial': 7, 'refresh': 3600,
       'retry': 600, 'expire': 1209600, 'minimum': 300}


def rec(owner, rtype, data, ttl=None):
    return {'owner': owner, 'type': rtype, 'ttl': ttl, 'data': data}


def cycle_input(with_glue):
    records = [
        rec('@', 'SOA', SOA), rec('@', 'NS', 'ns1'), rec('ns1', 'A', '192.0.2.53'),
        rec('a', 'NS', 'ns.b'), rec('a', 'NS', 'boot.a'), rec('b', 'NS', 'ns.a'),
    ]
    if with_glue:
        records.append(rec('boot.a', 'A', '192.0.2.10'))
    return {
        'zones': [
            {'origin': 'example.test.', 'default_ttl': 3600, 'records': records},
            {'origin': 'a.example.test.', 'default_ttl': 3600, 'records': [
                rec('@', 'SOA', SOA), rec('@', 'NS', 'ns'),
                rec('ns', 'A', '192.0.2.1'), rec('boot', 'A', '192.0.2.2')]},
            {'origin': 'b.example.test.', 'default_ttl': 3600, 'records': [
                rec('@', 'SOA', SOA), rec('@', 'NS', 'ns'), rec('ns', 'A', '192.0.2.3')]},
        ],
        'roots': ['example.test.'],
    }


class BootstrapCliTests(unittest.TestCase):
    def invoke(self, source, output):
        return subprocess.run([sys.executable, '-m', MODULE, '--source', str(source), '--output', str(output)],
                              capture_output=True, text=True, timeout=10)

    def write(self, directory, data):
        source = Path(directory) / 'input.json'
        source.write_text(json.dumps(data))
        return source

    def test_report_provenance_and_repeatable_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = self.write(temporary, cycle_input(with_glue=True))
            output = Path(temporary) / 'report.json'
            first = self.invoke(source, output)
            self.assertEqual(first.returncode, 0, first.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report, json.loads(first.stdout))
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['source_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(set(report['result']), {'zones', 'all_reachable'})
            self.assertTrue(report['result']['all_reachable'])
            rounds = {z['origin']: z['round'] for z in report['result']['zones']}
            self.assertEqual(rounds, {'example.test.': 0, 'a.example.test.': 1, 'b.example.test.': 2})
            original = output.read_bytes()
            self.assertEqual(self.invoke(source, output).returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    def test_equivalent_input_same_result_new_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = cycle_input(with_glue=True)
            variant = {
                'roots': ['EXAMPLE.TEST.'],
                'zones': [
                    {'origin': 'B.EXAMPLE.TEST.', 'default_ttl': 3600, 'records': list(reversed(base['zones'][2]['records']))},
                    {'origin': 'Example.Test.', 'default_ttl': 3600, 'records': list(reversed(base['zones'][0]['records']))},
                    {'origin': 'a.Example.TEST.', 'default_ttl': 3600, 'records': list(reversed(base['zones'][1]['records']))},
                ],
            }
            reports = []
            for name, data in [('base', base), ('variant', variant)]:
                source = self.write(temporary, data)
                output = Path(temporary) / (name + '.json')
                self.assertEqual(self.invoke(source, output).returncode, 0)
                reports.append(json.loads(output.read_text()))
            self.assertEqual(reports[0]['result'], reports[1]['result'])
            self.assertNotEqual(reports[0]['source_sha256'], reports[1]['source_sha256'])

    def test_unbootstrappable_but_legal_input_still_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = self.write(temporary, cycle_input(with_glue=False))
            output = Path(temporary) / 'report.json'
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertFalse(report['result']['all_reachable'])
            for zone in report['result']['zones']:
                if zone['parent'] is not None:
                    self.assertIsNone(zone['round'])
                    self.assertIsNone(zone['witness'])

    def test_contract_error_preserves_previous_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            output.write_text('previous report')
            bad = cycle_input(with_glue=False)
            bad['zones'][0]['records'] = [r for r in bad['zones'][0]['records']
                                          if not (r['owner'] == 'a' and r['type'] == 'NS')]
            source = self.write(temporary, bad)
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 2)
            self.assertIn('delegation', result.stderr)
            self.assertEqual(output.read_text(), 'previous report')

    def test_malformed_inputs_preserve_previous_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            output.write_text('previous report')
            source = Path(temporary) / 'bad.json'
            for raw in ('{', '{"zones":1,"zones":2}', '{"zones":NaN}', '{}',
                        '{"zones":[],"roots":[]}',
                        '{"zones":[{"origin":"example.test.","default_ttl":1,"records":[]}],"roots":["example.test"]}'):
                with self.subTest(raw=raw):
                    source.write_text(raw)
                    result = self.invoke(source, output)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(output.read_text(), 'previous report')

    def test_missing_source_and_output_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            self.assertEqual(self.invoke(Path(temporary) / 'absent.json', output).returncode, 2)
            self.assertFalse(output.exists())
            source = self.write(temporary, cycle_input(with_glue=True))
            original = source.read_bytes()
            self.assertEqual(self.invoke(source, source).returncode, 2)
            self.assertEqual(source.read_bytes(), original)

    def test_symlink_output_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'target'
            target.write_text('unchanged')
            output = Path(temporary) / 'report.json'
            output.symlink_to(target)
            source = self.write(temporary, cycle_input(with_glue=True))
            self.assertEqual(self.invoke(source, output).returncode, 2)
            self.assertEqual(target.read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main()
