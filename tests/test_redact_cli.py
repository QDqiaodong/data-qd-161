import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from dns_zone_audit.redact import analyze

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'dns_zone_audit.redact_cli'


def sample():
    return {
        'origin': 'example.test.',
        'default_ttl': 3600,
        'records': [
            {'owner': '@', 'type': 'SOA', 'ttl': None,
             'data': {'mname': 'ns1', 'rname': 'hostmaster', 'serial': 7,
                      'refresh': 3600, 'retry': 600, 'expire': 1209600,
                      'minimum': 300}},
            {'owner': '@', 'type': 'NS', 'ttl': None, 'data': 'ns1'},
            {'owner': 'ns1', 'type': 'A', 'ttl': 300, 'data': '192.0.2.53'},
        ],
    }


class RedactCliTests(unittest.TestCase):
    def invoke(self, source, output):
        return subprocess.run([sys.executable, '-m', MODULE, '--source', str(source),
                               '--output', str(output)],
                              capture_output=True, text=True, timeout=30)

    def write(self, directory, data):
        source = Path(directory) / 'input.json'
        source.write_text(json.dumps(data))
        return source

    def test_published_report_matches_stdout_and_repeat(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = ROOT / 'fixtures/redact-input.json'
            output = Path(temporary) / 'report.json'
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report, json.loads(result.stdout))
            self.assertEqual(set(report), {'schema_version', 'result'})
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(set(report['result']), {'names', 'groups'})
            # The input digest is provenance and must not be published.
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertNotIn(digest, output.read_text())
            self.assertNotIn(digest, result.stdout)
            original = output.read_bytes()
            self.assertEqual(self.invoke(source, output).returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    def test_cli_wraps_interface_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = ROOT / 'fixtures/redact-input.json'
            output = Path(temporary) / 'report.json'
            self.assertEqual(self.invoke(source, output).returncode, 0)
            report = json.loads(output.read_text())
            self.assertEqual(report['result'],
                             analyze(json.loads(source.read_text())))

    def test_zone_with_findings_still_exports(self):
        # fixtures/input.json carries an in_zone_glue_missing finding; a
        # legal snapshot with local findings exports normally.
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            result = self.invoke(ROOT / 'fixtures/input.json', output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(set(report['result']), {'names', 'groups'})

    def test_invalid_inputs_preserve_existing_report(self):
        valid = sample()
        bad_type = json.loads(json.dumps(valid))
        bad_type['records'][2]['type'] = 'SRV'
        bad_owner = json.loads(json.dumps(valid))
        bad_owner['records'][2]['owner'] = 'ns1.other.test.'
        duplicate = json.loads(json.dumps(valid))
        duplicate['records'].append(dict(duplicate['records'][1]))
        cases = ['{', '{"origin":"x.","origin":"y."}', '{"origin":NaN}', '{}',
                 '[]'] + [json.dumps(data) for data in (bad_type, bad_owner, duplicate)]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            source = Path(temporary) / 'input.json'
            output.write_text('previous report')
            for raw in cases:
                with self.subTest(raw=raw[:60]):
                    source.write_text(raw)
                    result = self.invoke(source, output)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertEqual(output.read_text(), 'previous report')

    def test_error_diagnostic_never_echoes_input_content(self):
        cases = [
            ('{"secrettoken": 1, "secrettoken": 2}', 'secrettoken'),
            (json.dumps({'origin': 'example.test.', 'default_ttl': 3600,
                         'records': [{'owner': 'bad..secretname', 'type': 'A',
                                      'ttl': None, 'data': '192.0.2.1'}]}),
             'secretname'),
            (json.dumps({'origin': 'example.test.', 'default_ttl': 3600,
                         'records': [{'owner': 'x', 'type': 'SECRETPROTO',
                                      'ttl': None, 'data': 'y'}]}),
             'SECRETPROTO'),
            (json.dumps({'origin': 'example.test.', 'default_ttl': 3600,
                         'records': [{'owner': 'x', 'type': 'A',
                                      'ttl': None, 'data': '192.0.2.999'}]}),
             '192.0.2.999'),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'input.json'
            output = Path(temporary) / 'report.json'
            for raw, needle in cases:
                with self.subTest(needle=needle):
                    source.write_text(raw)
                    result = self.invoke(source, output)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn(needle, result.stderr)
                    self.assertFalse(output.exists())
            source.write_bytes(b'{"origin": "example.test.", "default_ttl": 3600, "records": [1, \xff]}')
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr.strip(), 'input is not valid UTF-8')

    def test_source_output_collision_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = self.write(temporary, sample())
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
