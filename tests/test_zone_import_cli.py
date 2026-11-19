import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'dns_zone_audit.zone_import_cli'


def sample():
    return {
        'origin': 'example.test.',
        'default_ttl': 3600,
        'entry': 'main',
        'fragments': {
            'main': '$ORIGIN one.example.test.\n$TTL 300\nwww A 192.0.2.1\n$INCLUDE shared\n'
                    '$ORIGIN two.example.test.\n$TTL 600\nmail A 192.0.2.2\n$INCLUDE shared',
            'shared': '  MX 10 relay',
        },
    }


class ZoneImportCliTests(unittest.TestCase):
    def invoke(self, source, output):
        return subprocess.run([sys.executable, '-m', MODULE, '--source', str(source),
                               '--output', str(output)],
                              capture_output=True, text=True, timeout=30)

    def write(self, directory, data):
        source = Path(directory) / 'input.json'
        source.write_text(json.dumps(data))
        return source

    def test_published_report_matches_stdout_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = self.write(temporary, sample())
            output = Path(temporary) / 'report.json'
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report, json.loads(result.stdout))
            self.assertEqual(set(report), {'schema_version', 'source_sha256', 'result'})
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['source_sha256'],
                             hashlib.sha256(source.read_bytes()).hexdigest())
            body = report['result']
            self.assertEqual(set(body), {'zone', 'sources'})
            self.assertEqual(set(body['zone']), {'origin', 'default_ttl', 'records'})
            self.assertEqual(len(body['sources']), len(body['zone']['records']))
            mx = [record for record in body['zone']['records'] if record['type'] == 'MX']
            self.assertEqual([record['owner'] for record in mx],
                             ['mail.two.example.test.', 'www.one.example.test.'])
            self.assertEqual([record['ttl'] for record in mx], [600, 300])
            self.assertEqual(mx[0]['data']['exchange'], 'relay.two.example.test.')
            self.assertEqual(mx[1]['data']['exchange'], 'relay.one.example.test.')
            chains = [body['sources'][body['zone']['records'].index(record)]
                      ['include_chain'] for record in mx]
            self.assertEqual(chains, [[{'fragment': 'main', 'line': 8}],
                                      [{'fragment': 'main', 'line': 4}]])
            original = output.read_bytes()
            self.assertEqual(self.invoke(source, output).returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    def test_fixture_report_is_stable_and_zone_feeds_existing_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = ROOT / 'fixtures/zone-import-input.json'
            first = Path(temporary) / 'first.json'
            second = Path(temporary) / 'second.json'
            self.assertEqual(self.invoke(source, first).returncode, 0)
            self.assertEqual(self.invoke(source, second).returncode, 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            report = json.loads(first.read_text())
            result = report['result']
            self.assertEqual(len(result['sources']), len(result['zone']['records']))
            self.assertIn('relay.one.example.test.', json.dumps(result['zone']['records']))
            zone_source = Path(temporary) / 'zone.json'
            zone_source.write_text(json.dumps(result['zone']))
            audit_output = Path(temporary) / 'audit.json'
            audit = subprocess.run([sys.executable, '-m', 'dns_zone_audit.cli',
                                    '--source', str(zone_source),
                                    '--output', str(audit_output)],
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(audit.returncode, 0, audit.stderr)
            audited = json.loads(audit_output.read_text())['result']
            self.assertTrue(audited['valid'])
            self.assertEqual(audited['records'], result['zone']['records'])

    def test_invalid_inputs_preserve_existing_report(self):
        valid = sample()
        bad = []
        unknown = json.loads(json.dumps(valid))
        unknown['fragments']['main'] = '$INCLUDE absent'
        bad.append(unknown)
        cycle = json.loads(json.dumps(valid))
        cycle['fragments']['main'] = '$INCLUDE main'
        bad.append(cycle)
        duplicate = json.loads(json.dumps(valid))
        duplicate['fragments']['main'] = '$INCLUDE shared\n$INCLUDE shared'
        bad.append(duplicate)
        syntax = json.loads(json.dumps(valid))
        syntax['fragments']['shared'] = '  MX 10 "relay'
        bad.append(syntax)
        no_owner = json.loads(json.dumps(valid))
        no_owner['fragments']['main'] = '  A 192.0.2.1'
        bad.append(no_owner)
        bad_id = json.loads(json.dumps(valid))
        bad_id['fragments']['bad id'] = ''
        bad_id['fragments']['main'] = ''
        bad.append(bad_id)
        not_text = json.loads(json.dumps(valid))
        not_text['fragments']['shared'] = ['not', 'text']
        bad.append(not_text)
        no_entry = json.loads(json.dumps(valid))
        no_entry['entry'] = 'absent'
        bad.append(no_entry)
        cases = ['{', '{"entry":"main","entry":"main"}', '{"entry":NaN}', '{}']
        cases += [json.dumps(data) for data in bad]
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

    def test_body_error_diagnostic_carries_full_position(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = sample()
            data['fragments']['shared'] = '  MX 10 relay\n  A 192.0.2.999'
            source = self.write(temporary, data)
            output = Path(temporary) / 'report.json'
            result = self.invoke(source, output)
            self.assertEqual(result.returncode, 2)
            self.assertIn('"fragment": "shared"', result.stderr)
            self.assertIn('"line": 2', result.stderr)
            self.assertIn('"include_chain": [{"fragment": "main", "line": 4}]',
                          result.stderr)
            self.assertFalse(output.exists())

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
