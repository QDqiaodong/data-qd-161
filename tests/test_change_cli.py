import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'dns_zone_audit'


class ChangeCliTests(unittest.TestCase):
    def invoke(self, source, output):
        return subprocess.run([sys.executable, '-m', MODULE + '.change_cli', '--source', str(source), '--output', str(output)], capture_output=True, text=True, timeout=10)

    def test_published_report_matches_stdout_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            source = ROOT / 'fixtures/change-input.json'
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report, json.loads(result.stdout))
            self.assertEqual(set(report), {'schema_version', 'source_sha256', 'result'})
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['source_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            body = report['result']
            self.assertEqual(set(body), {'origin', 'serial', 'can_publish', 'changes', 'summary'})
            self.assertEqual(body['origin'], 'example.test.')
            self.assertEqual(body['serial'], {'current': 4294967295, 'candidate': 0, 'delta': 1, 'relation': 'newer'})
            self.assertTrue(body['can_publish'])
            # Current SOA serial differs in RDATA, so it is removed plus added;
            # the A TTL change stays a TTL change rather than add/delete.
            self.assertEqual(body['summary'], {'added': 2, 'removed': 1, 'ttl_changed': 1, 'unchanged': 4})
            self.assertTrue(any(c['change'] == 'ttl_changed' and c['identity']['type'] == 'A'
                                for c in body['changes']))

    def test_repeat_run_is_stable_and_ordered(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = ROOT / 'fixtures/change-input.json'
            first = Path(temporary) / 'first.json'
            second = Path(temporary) / 'second.json'
            self.assertEqual(self.invoke(source, first).returncode, 0)
            self.assertEqual(self.invoke(source, second).returncode, 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            changes = json.loads(first.read_text())['result']['changes']
            keys = [(c['identity']['owner'], c['identity']['type'],
                     json.dumps(c['identity']['data'], sort_keys=True), c['change']) for c in changes]
            self.assertEqual(keys, sorted(keys))

    def test_older_serial_still_succeeds_without_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = ROOT / 'fixtures/change-input.json'
            data = json.loads(source.read_text())
            data['candidate']['records'][1]['data']['serial'] = 4294967294
            reversed_source = Path(temporary) / 'input.json'
            reversed_source.write_text(json.dumps(data))
            output = Path(temporary) / 'report.json'
            result = self.invoke(reversed_source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            body = json.loads(output.read_text())['result']
            self.assertEqual(body['serial']['relation'], 'older')
            self.assertFalse(body['can_publish'])

    def test_invalid_inputs_preserve_existing_report(self):
        valid = json.loads((ROOT / 'fixtures/change-input.json').read_text())
        malformed = ['{', '{"current":{},"current":{}}', '{"current":{},"candidate":{}}',
                     '{"current":NaN,"candidate":{}}']
        other_origin = json.loads(json.dumps(valid))
        other_origin['candidate']['origin'] = 'other.test.'
        no_soa = json.loads(json.dumps(valid))
        no_soa['candidate']['records'] = [r for r in no_soa['candidate']['records'] if r['type'] != 'SOA']
        duplicate_soa = json.loads(json.dumps(valid))
        duplicate_soa['candidate']['records'].append(duplicate_soa['candidate']['records'][1])
        bad_record = json.loads(json.dumps(valid))
        bad_record['candidate']['records'][0]['ttl'] = -1
        cases = malformed + [json.dumps(x) for x in (other_origin, no_soa, duplicate_soa, bad_record)]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            source = Path(temporary) / 'input.json'
            output.write_text('previous report')
            for raw in cases:
                with self.subTest(raw=raw[:40]):
                    source.write_text(raw)
                    result = self.invoke(source, output)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertEqual(output.read_text(), 'previous report')

    def test_source_output_collision_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'input.json'
            source.write_bytes((ROOT / 'fixtures/change-input.json').read_bytes())
            original = source.read_bytes()
            self.assertEqual(self.invoke(source, source).returncode, 2)
            self.assertEqual(source.read_bytes(), original)
            target = Path(temporary) / 'target'
            target.write_text('unchanged')
            link = Path(temporary) / 'report.json'
            link.symlink_to(target)
            self.assertEqual(self.invoke(source, link).returncode, 2)
            self.assertEqual(target.read_text(), 'unchanged')

    def test_missing_source_does_not_create_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            self.assertEqual(self.invoke(Path(temporary) / 'absent.json', output).returncode, 2)
            self.assertFalse(output.exists())
