import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'dns_zone_audit.wildcard_cli'

SOA = {'mname': 'ns1', 'rname': 'hostmaster', 'serial': 7, 'refresh': 3600,
       'retry': 600, 'expire': 1209600, 'minimum': 300}


def rec(owner, rtype, data, ttl=None):
    return {'owner': owner, 'type': rtype, 'ttl': ttl, 'data': data}


def wildcard_input():
    return {
        'zone': {'origin': 'example.test.', 'default_ttl': 3600, 'records': [
            rec('@', 'SOA', SOA), rec('@', 'NS', 'ns1'), rec('ns1', 'A', '192.0.2.53'),
            rec('*', 'A', '192.0.2.10'), rec('branch', 'NS', 'ns.branch'),
        ]},
        'queries': ['anything', 'x.branch', 'branch'],
    }


class WildcardCliTests(unittest.TestCase):
    def invoke(self, source, output):
        return subprocess.run([sys.executable, '-m', MODULE, '--source', str(source), '--output', str(output)],
                              capture_output=True, text=True, timeout=10)

    def write(self, directory, data):
        source = Path(directory) / 'input.json'
        source.write_text(json.dumps(data))
        return source

    def test_published_report_matches_stdout_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = self.write(temporary, wildcard_input())
            output = Path(temporary) / 'report.json'
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report, json.loads(result.stdout))
            self.assertEqual(set(report), {'schema_version', 'source_sha256', 'result'})
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['source_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            body = report['result']
            self.assertEqual(set(body), {'origin', 'answers'})
            states = {a['query']: a['state'] for a in body['answers']}
            self.assertEqual(states, {'anything.example.test.': 'wildcard',
                                      'branch.example.test.': 'explicit',
                                      'x.branch.example.test.': 'delegated'})
            original = output.read_bytes()
            self.assertEqual(self.invoke(source, output).returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    def test_fixture_report_is_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = ROOT / 'fixtures/wildcard-input.json'
            first = Path(temporary) / 'first.json'
            second = Path(temporary) / 'second.json'
            self.assertEqual(self.invoke(source, first).returncode, 0)
            self.assertEqual(self.invoke(source, second).returncode, 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            answers = json.loads(first.read_text())['result']['answers']
            keys = [a['query'] for a in answers]
            self.assertEqual(keys, sorted(keys))

    def test_invalid_inputs_preserve_existing_report(self):
        valid = wildcard_input()
        cases = ['{', '{"zone":{},"zone":{}}', '{"zone":NaN,"queries":["x"]}', '{}']
        bad = []
        duplicate = json.loads(json.dumps(valid))
        duplicate['queries'] = ['x', 'X.example.test.']
        bad.append(duplicate)
        outside = json.loads(json.dumps(valid))
        outside['queries'] = ['x.other.test.']
        bad.append(outside)
        bad_wildcard = json.loads(json.dumps(valid))
        bad_wildcard['zone']['records'].append(rec('a.*.b', 'A', '192.0.2.1'))
        bad.append(bad_wildcard)
        bad_rdata = json.loads(json.dumps(valid))
        bad_rdata['zone']['records'].append(rec('alias', 'CNAME', '*'))
        bad.append(bad_rdata)
        over_limit = json.loads(json.dumps(valid))
        over_limit['queries'] = ['h%d' % i for i in range(1001)]
        bad.append(over_limit)
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
            source = self.write(temporary, wildcard_input())
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
