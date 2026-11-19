import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'dns_zone_audit.cache_replay_cli'
FIXTURE = ROOT / 'fixtures/cache-replay-input.json'


class CacheReplayCliTests(unittest.TestCase):
    def invoke(self, source, output):
        return subprocess.run([sys.executable, '-m', MODULE, '--source', str(source), '--output', str(output)],
                              capture_output=True, text=True, timeout=10)

    def test_published_report_matches_stdout_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            result = self.invoke(FIXTURE, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report, json.loads(result.stdout))
            self.assertEqual(set(report), {'schema_version', 'source_sha256', 'result'})
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['source_sha256'], hashlib.sha256(FIXTURE.read_bytes()).hexdigest())
            body = report['result']
            self.assertEqual(set(body), {'probes'})
            statuses = [p['status'] for p in body['probes']]
            self.assertEqual(statuses, ['hit', 'nxdomain', 'miss', 'miss', 'hit'])
            self.assertEqual([p['seq'] for p in body['probes']], sorted(p['seq'] for p in body['probes']))

    def test_repeat_run_is_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / 'first.json'
            second = Path(temporary) / 'second.json'
            self.assertEqual(self.invoke(FIXTURE, first).returncode, 0)
            self.assertEqual(self.invoke(FIXTURE, second).returncode, 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_event_array_order_does_not_change_report(self):
        data = json.loads(FIXTURE.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            ordered = Path(temporary) / 'ordered.json'
            shuffled = Path(temporary) / 'shuffled.json'
            self.assertEqual(self.invoke(FIXTURE, ordered).returncode, 0)
            reversed_source = Path(temporary) / 'input.json'
            reversed_source.write_text(json.dumps({'events': list(reversed(data['events']))}))
            self.assertEqual(self.invoke(reversed_source, shuffled).returncode, 0)
            first = json.loads(ordered.read_text())['result']
            second = json.loads(shuffled.read_text())['result']
            by_seq = lambda probes: sorted(probes, key=lambda p: p['seq'])
            self.assertEqual(by_seq(first['probes']), by_seq(second['probes']))

    def test_invalid_inputs_preserve_existing_report(self):
        valid = json.loads(FIXTURE.read_text())
        cases = ['{', '{"events":[],"events":[]}', '{"events":NaN}', '{}',
                 '{"events":[]}', '{"events":[{"seq":1,"at":0,"name":"b.example.test.",'
                 '"kind":"probe","qtype":"MX"}]}']
        bad = []
        duplicate_seq = json.loads(json.dumps(valid))
        duplicate_seq['events'][1]['seq'] = duplicate_seq['events'][0]['seq']
        bad.append(duplicate_seq)
        retreat = json.loads(json.dumps(valid))
        retreat['events'][2]['at'] = 99
        bad.append(retreat)
        extra_field = json.loads(json.dumps(valid))
        extra_field['events'][0]['extra'] = 1
        bad.append(extra_field)
        relative = json.loads(json.dumps(valid))
        relative['events'][0]['name'] = 'b.example.test'
        bad.append(relative)
        bad_address = json.loads(json.dumps(valid))
        bad_address['events'][0]['addresses'] = ['192.0.2.400']
        bad.append(bad_address)
        no_probe = json.loads(json.dumps(valid))
        no_probe['events'] = [e for e in no_probe['events'] if e['kind'] != 'probe']
        bad.append(no_probe)
        cases += [json.dumps(x) for x in bad]
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
            source.write_bytes(FIXTURE.read_bytes())
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


if __name__ == '__main__':
    unittest.main()
