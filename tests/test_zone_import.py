import unittest

from dns_zone_audit.model import analyze
from dns_zone_audit.zone_import import SourceError, compile_bundle


def bundle(fragments, entry='main', origin='example.test.', default_ttl=3600):
    return {'origin': origin, 'default_ttl': default_ttl, 'entry': entry,
            'fragments': fragments}


def one(text, **kwargs):
    return bundle({'main': text}, **kwargs)


def records_of(result, owner, rtype=None):
    return [record for record in result['zone']['records']
            if record['owner'] == owner and (rtype is None or record['type'] == rtype)]


def source_of(result, record):
    index = result['zone']['records'].index(record)
    return result['sources'][index]


class LinkedSampleTests(unittest.TestCase):
    """The shared fragment's first line is an indented ``MX 10 relay``; it
    inherits each caller's absolute owner, relative-name origin and TTL."""

    FRAGMENTS = {
        'main': '$ORIGIN one.example.test.\n$TTL 300\nwww A 192.0.2.1\n$INCLUDE shared\n'
                '$ORIGIN two.example.test.\n$TTL 600\nmail A 192.0.2.2\n$INCLUDE shared',
        'shared': '  MX 10 relay',
    }

    def test_shared_fragment_inherits_each_scope(self):
        result = compile_bundle(bundle(self.FRAGMENTS))
        first, = records_of(result, 'www.one.example.test.', 'MX')
        second, = records_of(result, 'mail.two.example.test.', 'MX')
        self.assertEqual(first['data'],
                         {'preference': 10, 'exchange': 'relay.one.example.test.'})
        self.assertEqual(first['ttl'], 300)
        self.assertEqual(second['data'],
                         {'preference': 10, 'exchange': 'relay.two.example.test.'})
        self.assertEqual(second['ttl'], 600)

    def test_same_physical_line_distinct_call_paths(self):
        result = compile_bundle(bundle(self.FRAGMENTS))
        first, = records_of(result, 'www.one.example.test.', 'MX')
        second, = records_of(result, 'mail.two.example.test.', 'MX')
        self.assertEqual(source_of(result, first),
                         {'fragment': 'shared', 'line': 1,
                          'include_chain': [{'fragment': 'main', 'line': 4}]})
        self.assertEqual(source_of(result, second),
                         {'fragment': 'shared', 'line': 1,
                          'include_chain': [{'fragment': 'main', 'line': 8}]})


class ScopeRestoreTests(unittest.TestCase):
    """A nested fragment changes origin, TTL and owner; on return the outer
    fragment's environment is restored first, then the entry's."""

    FRAGMENTS = {
        'main': '$TTL 100\nalpha A 192.0.2.1\n$INCLUDE mid\n  A 192.0.2.9',
        'mid': '$TTL 200\nbeta A 192.0.2.2\n$INCLUDE leaf\n  A 192.0.2.3',
        'leaf': '$ORIGIN three.example.test.\n$TTL 300\ndelta A 192.0.2.4',
    }

    def test_nested_changes_are_undone_outward(self):
        result = compile_bundle(bundle(self.FRAGMENTS))
        addresses = {}
        ttls = {}
        for record in result['zone']['records']:
            addresses.setdefault(record['owner'], []).append(record['data'])
            ttls[(record['owner'], record['data'])] = record['ttl']
        # Indented lines after $INCLUDE reuse the restored outer owner,
        # origin and TTL — the leaf's $ORIGIN/$TTL/owner changes are undone
        # for the mid fragment first and for the entry after that.
        self.assertEqual(addresses, {
            'alpha.example.test.': ['192.0.2.1', '192.0.2.9'],
            'beta.example.test.': ['192.0.2.2', '192.0.2.3'],
            'delta.three.example.test.': ['192.0.2.4'],
        })
        self.assertEqual(ttls, {
            ('alpha.example.test.', '192.0.2.1'): 100,
            ('alpha.example.test.', '192.0.2.9'): 100,
            ('beta.example.test.', '192.0.2.2'): 200,
            ('beta.example.test.', '192.0.2.3'): 200,
            ('delta.three.example.test.', '192.0.2.4'): 300,
        })

    def test_leaf_record_carries_two_step_chain(self):
        result = compile_bundle(bundle(self.FRAGMENTS))
        leaf, = records_of(result, 'delta.three.example.test.')
        self.assertEqual(source_of(result, leaf),
                         {'fragment': 'leaf', 'line': 3,
                          'include_chain': [{'fragment': 'main', 'line': 3},
                                            {'fragment': 'mid', 'line': 3}]})


class RevisitAndCycleTests(unittest.TestCase):
    def test_second_visit_after_return_is_legal(self):
        result = compile_bundle(bundle({
            'main': '$ORIGIN one.example.test.\n$INCLUDE sub\n'
                    '$ORIGIN two.example.test.\n$INCLUDE sub',
            'sub': 'x A 192.0.2.1',
        }))
        owners = sorted(record['owner'] for record in result['zone']['records'])
        self.assertEqual(owners, ['x.one.example.test.', 'x.two.example.test.'])

    def test_diamond_revisit_is_not_a_cycle(self):
        result = compile_bundle(bundle({
            'main': '$ORIGIN one.example.test.\n$INCLUDE a\n'
                    '$ORIGIN two.example.test.\n$INCLUDE b',
            'a': '$INCLUDE c',
            'b': '$INCLUDE c',
            'c': 'x A 192.0.2.1',
        }))
        owners = sorted(record['owner'] for record in result['zone']['records'])
        self.assertEqual(owners, ['x.one.example.test.', 'x.two.example.test.'])

    def test_same_environment_twice_reports_both_chains(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(bundle({
                'main': '$INCLUDE sub\n$INCLUDE sub',
                'sub': 'x A 192.0.2.1',
            }))
        error = caught.exception
        self.assertIn('duplicate DNS record', str(error))
        first, again = error.positions
        self.assertEqual(first, {'fragment': 'sub', 'line': 1,
                                 'include_chain': [{'fragment': 'main', 'line': 1}]})
        self.assertEqual(again, {'fragment': 'sub', 'line': 1,
                                 'include_chain': [{'fragment': 'main', 'line': 2}]})
        self.assertIn('"line": 1', str(error))
        self.assertIn('"line": 2', str(error))

    def test_active_chain_cycle_is_rejected(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(bundle({
                'main': '$INCLUDE a',
                'a': '$INCLUDE b',
                'b': '$INCLUDE a',
            }))
        self.assertIn('include cycle: a', str(caught.exception))
        position, = caught.exception.positions
        self.assertEqual(position, {'fragment': 'b', 'line': 1,
                                    'include_chain': [{'fragment': 'main', 'line': 1},
                                                      {'fragment': 'a', 'line': 1}]})

    def test_self_include_is_a_cycle(self):
        with self.assertRaisesRegex(SourceError, 'include cycle: main'):
            compile_bundle(one('$INCLUDE main'))


class BudgetTests(unittest.TestCase):
    def test_expanded_line_budget_counts_blank_and_comment_lines(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(one('\n' * 20001))
        self.assertIn('expanded line budget exceeded', str(caught.exception))
        position, = caught.exception.positions
        self.assertEqual(position['fragment'], 'main')
        self.assertEqual(position['line'], 20001)

    def test_expanded_line_budget_accumulates_per_occurrence(self):
        fragments = {'main': '\n'.join(['$INCLUDE sub'] * 21), 'sub': '; x\n' * 1000}
        with self.assertRaisesRegex(SourceError, 'expanded line budget exceeded'):
            compile_bundle(bundle(fragments))

    def test_exact_line_budget_is_allowed(self):
        result = compile_bundle(one('; pad\n' * 9999 + 'x A 192.0.2.1'))
        self.assertEqual(len(result['zone']['records']), 1)

    def test_record_budget(self):
        text = '\n'.join('h%d A 192.0.2.1' % index for index in range(10001))
        with self.assertRaises(SourceError) as caught:
            compile_bundle(one(text))
        self.assertIn('record budget exceeded', str(caught.exception))
        position, = caught.exception.positions
        self.assertEqual(position['line'], 10001)

    def test_depth_limit_sixteen(self):
        fragments = {'f%d' % index: '$INCLUDE f%d' % (index + 1) for index in range(16)}
        fragments['f16'] = ''
        with self.assertRaises(SourceError) as caught:
            compile_bundle(bundle(fragments, entry='f0'))
        self.assertIn('include depth exceeded', str(caught.exception))
        position, = caught.exception.positions
        self.assertEqual(position['fragment'], 'f15')
        self.assertEqual(position['line'], 1)
        self.assertEqual(len(position['include_chain']), 15)

    def test_depth_sixteen_is_allowed(self):
        fragments = {'f%d' % index: '$INCLUDE f%d' % (index + 1) for index in range(15)}
        fragments['f15'] = 'x A 192.0.2.1'
        result = compile_bundle(bundle(fragments, entry='f0'))
        record, = result['zone']['records']
        self.assertEqual(record['owner'], 'x.example.test.')
        source, = result['sources']
        self.assertEqual(len(source['include_chain']), 15)


class OwnerRuleTests(unittest.TestCase):
    def test_indented_record_without_any_owner_fails(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(one('  A 192.0.2.1'))
        self.assertIn('no previous explicit owner', str(caught.exception))
        position, = caught.exception.positions
        self.assertEqual(position, {'fragment': 'main', 'line': 1, 'include_chain': []})

    def test_included_fragment_inherits_absence_of_owner(self):
        with self.assertRaisesRegex(SourceError, 'no previous explicit owner'):
            compile_bundle(bundle({'main': '$INCLUDE sub', 'sub': '  A 192.0.2.1'}))

    def test_owner_survives_blank_and_comment_lines(self):
        result = compile_bundle(one('x A 192.0.2.1\n; note\n\n\tA 192.0.2.2'))
        self.assertEqual(len(records_of(result, 'x.example.test.')), 2)

    def test_origin_change_does_not_rebind_previous_owner(self):
        result = compile_bundle(one(
            'x A 192.0.2.1\n$ORIGIN sub.example.test.\n  A 192.0.2.2'))
        owners = sorted(record['owner'] for record in result['zone']['records'])
        self.assertEqual(owners, ['x.example.test.', 'x.example.test.'])

    def test_at_owner_uses_current_scope_origin(self):
        result = compile_bundle(one('$ORIGIN sub.example.test.\n@ A 192.0.2.1'))
        self.assertEqual(records_of(result, 'sub.example.test.')[0]['owner'],
                         'sub.example.test.')

    def test_wildcard_owner_allowed_but_not_in_rdata(self):
        result = compile_bundle(one('* A 192.0.2.1\n*.x A 192.0.2.2'))
        self.assertEqual(sorted(record['owner'] for record in result['zone']['records']),
                         ['*.example.test.', '*.x.example.test.'])
        with self.assertRaisesRegex(SourceError, 'invalid DNS name'):
            compile_bundle(one('x CNAME *'))
        with self.assertRaisesRegex(SourceError, 'invalid DNS name'):
            compile_bundle(one('x MX 10 *'))


class DuplicateIdentityTests(unittest.TestCase):
    def test_equivalent_aaaa_forms_collide(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(one('x AAAA 2001:0db8::1\ny A 192.0.2.1\nx AAAA 2001:db8::1'))
        self.assertIn('duplicate DNS record', str(caught.exception))
        first, again = caught.exception.positions
        self.assertEqual(first['line'], 1)
        self.assertEqual(again['line'], 3)

    def test_ttl_is_not_part_of_identity(self):
        with self.assertRaisesRegex(SourceError, 'duplicate DNS record'):
            compile_bundle(one('$TTL 100\nx A 192.0.2.1\nx 200 A 192.0.2.1'))

    def test_same_name_different_type_is_not_a_duplicate(self):
        result = compile_bundle(one('x A 192.0.2.1\nx TXT "note"'))
        self.assertEqual(len(records_of(result, 'x.example.test.')), 2)


class QuoteAndCommentTests(unittest.TestCase):
    def test_quoted_semicolon_escapes_and_comment(self):
        result = compile_bundle(one(
            'x TXT "a;not a comment" ; a real comment\n'
            'y TXT "quote \\" and slash \\\\" ; done\n'
            'z TXT ""'))
        data = {record['owner']: record['data'] for record in result['zone']['records']}
        self.assertEqual(data['x.example.test.'], 'a;not a comment')
        self.assertEqual(data['y.example.test.'], 'quote " and slash \\')
        self.assertEqual(data['z.example.test.'], '')

    def test_unclosed_quote(self):
        with self.assertRaisesRegex(SourceError, 'unclosed quoted string'):
            compile_bundle(one('x TXT "abc'))

    def test_unsupported_escape(self):
        with self.assertRaisesRegex(SourceError, 'unsupported escape'):
            compile_bundle(one(r'x TXT "a\qb"'))

    def test_content_after_closing_quote(self):
        with self.assertRaisesRegex(SourceError, 'followed by a separator'):
            compile_bundle(one('x TXT "a"b'))

    def test_quote_inside_bare_token(self):
        with self.assertRaisesRegex(SourceError, 'quote must start a token'):
            compile_bundle(one('x A 192.0.2."1"'))

    def test_txt_payload_must_be_quoted(self):
        with self.assertRaisesRegex(SourceError, 'TXT data must be a quoted string'):
            compile_bundle(one('x TXT hello'))

    def test_quotes_rejected_outside_txt(self):
        for text in ('"x" A 192.0.2.1', 'x "A" 192.0.2.1', 'x NS "ns1"',
                     '$TTL "300"', '$INCLUDE "sub"'):
            with self.subTest(text=text):
                with self.assertRaisesRegex(SourceError, 'only valid as TXT'):
                    compile_bundle(bundle({'main': text, 'sub': ''}))


class StructureTests(unittest.TestCase):
    def test_top_level_keys_are_strict(self):
        with self.assertRaises(ValueError):
            compile_bundle({'origin': 'example.test.', 'default_ttl': 3600,
                            'entry': 'main'})
        data = bundle({'main': ''})
        data['extra'] = 1
        with self.assertRaises(ValueError):
            compile_bundle(data)

    def test_fragment_count_bounds(self):
        with self.assertRaisesRegex(ValueError, '1 to 128'):
            compile_bundle(bundle({}))
        fragments = {'f%d' % index: '' for index in range(129)}
        with self.assertRaisesRegex(ValueError, '1 to 128'):
            compile_bundle(bundle(fragments, entry='f0'))
        fragments = {'f%d' % index: '' for index in range(128)}
        self.assertEqual(compile_bundle(bundle(fragments, entry='f0'))['sources'], [])

    def test_fragment_ids_are_case_sensitive_and_restricted(self):
        for bad in ('', 'has space', 'dot.name', '..' , 'x' * 65, 'semi;', 'slash/'):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, 'invalid fragment id'):
                    compile_bundle(bundle({bad: '', 'main': ''}))
        result = compile_bundle(bundle({'main': '$INCLUDE Sub', 'Sub': 'x A 192.0.2.1'}))
        self.assertEqual(len(result['sources']), 1)
        with self.assertRaisesRegex(SourceError, 'unknown fragment: sub'):
            compile_bundle(bundle({'main': '$INCLUDE sub', 'Sub': ''}))

    def test_unreferenced_fragments_are_still_validated(self):
        with self.assertRaisesRegex(ValueError, 'must be a string'):
            compile_bundle(bundle({'main': '', 'idle': 12}))
        with self.assertRaisesRegex(ValueError, 'invalid fragment id'):
            compile_bundle(bundle({'main': '', 'bad id': ''}))
        result = compile_bundle(bundle({'main': '', 'idle': 'not ( parsed'}))
        self.assertEqual(result['zone']['records'], [])

    def test_entry_must_exist(self):
        with self.assertRaisesRegex(ValueError, 'entry must name an existing fragment'):
            compile_bundle(bundle({'main': ''}, entry='absent'))
        with self.assertRaisesRegex(ValueError, 'entry must name an existing fragment'):
            compile_bundle(bundle({'main': ''}, entry=7))

    def test_header_rules_match_snapshot_rules(self):
        with self.assertRaises(ValueError):
            compile_bundle(one('', default_ttl=-1))
        with self.assertRaises(ValueError):
            compile_bundle(one('', default_ttl=2147483648))
        with self.assertRaises(ValueError):
            compile_bundle(one('', origin='bad name'))
        result = compile_bundle(one('', origin='EXAMPLE.test'))
        self.assertEqual(result['zone']['origin'], 'example.test.')

    def test_unknown_include_is_positioned(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(one('x A 192.0.2.1\n$INCLUDE missing'))
        self.assertIn('unknown fragment: missing', str(caught.exception))
        position, = caught.exception.positions
        self.assertEqual(position, {'fragment': 'main', 'line': 2, 'include_chain': []})


class DirectiveAndTypeTests(unittest.TestCase):
    def test_unknown_and_lowercase_directives(self):
        with self.assertRaisesRegex(SourceError, 'unknown directive: \\$FOO'):
            compile_bundle(one('$FOO bar'))
        with self.assertRaisesRegex(SourceError, 'unknown directive: \\$ttl'):
            compile_bundle(one('$ttl 300'))

    def test_directive_arity(self):
        with self.assertRaisesRegex(SourceError, 'exactly one argument'):
            compile_bundle(one('$TTL 300 400'))
        with self.assertRaisesRegex(SourceError, 'exactly one argument'):
            compile_bundle(one('$ORIGIN'))

    def test_indented_directive_is_still_a_directive(self):
        result = compile_bundle(one('  $TTL 42\nx A 192.0.2.1'))
        self.assertEqual(result['zone']['records'][0]['ttl'], 42)

    def test_origin_target_must_stay_in_zone(self):
        with self.assertRaisesRegex(SourceError, 'outside zone'):
            compile_bundle(one('$ORIGIN other.test.'))
        with self.assertRaisesRegex(SourceError, 'outside zone'):
            compile_bundle(one('$ORIGIN notexample.test.'))
        result = compile_bundle(one('$ORIGIN sub.example.test.\n$ORIGIN @\nx A 192.0.2.1'))
        self.assertEqual(result['zone']['records'][0]['owner'], 'x.sub.example.test.')

    def test_types_are_uppercase_and_known(self):
        with self.assertRaisesRegex(SourceError, 'unsupported record type: a'):
            compile_bundle(one('x a 192.0.2.1'))
        with self.assertRaisesRegex(SourceError, 'unsupported record type: SRV'):
            compile_bundle(one('x SRV 0 0 80 y'))

    def test_rdata_arity_and_numbers(self):
        with self.assertRaisesRegex(SourceError, 'exactly 1 RDATA'):
            compile_bundle(one('x A 192.0.2.1 192.0.2.2'))
        with self.assertRaisesRegex(SourceError, 'MX preference outside allowed bounds'):
            compile_bundle(one('x MX 65536 relay'))
        with self.assertRaisesRegex(SourceError, 'SOA serial outside allowed bounds'):
            compile_bundle(one('@ SOA ns1 hostmaster 4294967296 1 1 1 1'))
        with self.assertRaisesRegex(SourceError, 'TTL outside allowed bounds'):
            compile_bundle(one('x 2147483648 A 192.0.2.1'))
        with self.assertRaisesRegex(SourceError, 'record type required'):
            compile_bundle(one('x 300'))

    def test_model_validation_is_positioned(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(one('x A 192.0.2.999'))
        self.assertIn('192.0.2.999', str(caught.exception))
        position, = caught.exception.positions
        self.assertEqual(position['line'], 1)
        with self.assertRaisesRegex(SourceError, 'outside zone'):
            compile_bundle(one('x.other.test. A 192.0.2.1'))


class LineAndOrderTests(unittest.TestCase):
    def test_crlf_and_lf_are_equivalent(self):
        lf = compile_bundle(one('x A 192.0.2.1\ny A 192.0.2.2\n'))
        crlf = compile_bundle(one('x A 192.0.2.1\r\ny A 192.0.2.2\r\n'))
        self.assertEqual(lf, crlf)
        self.assertEqual([source['line'] for source in lf['sources']], [1, 2])

    def test_trailing_newline_adds_no_line(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(one('x A 192.0.2.1\nbad line here'))
        position, = caught.exception.positions
        self.assertEqual(position['line'], 2)

    def test_sources_follow_sorted_records_not_expansion_order(self):
        result = compile_bundle(one('z A 192.0.2.1\na A 192.0.2.2\nm A 192.0.2.3'))
        owners = [record['owner'] for record in result['zone']['records']]
        self.assertEqual(owners, ['a.example.test.', 'm.example.test.', 'z.example.test.'])
        self.assertEqual([source['line'] for source in result['sources']], [2, 3, 1])

    def test_zone_feeds_model_analyze_directly(self):
        result = compile_bundle(bundle({
            'main': '$ORIGIN one.example.test.\n$TTL 300\nwww A 192.0.2.1\n$INCLUDE shared',
            'shared': '  MX 10 relay',
        }))
        audit = analyze(result['zone'])
        self.assertEqual(audit['records'], result['zone']['records'])
        self.assertTrue(all(isinstance(record['ttl'], int)
                            for record in result['zone']['records']))

    def test_model_issues_do_not_fail_import(self):
        result = compile_bundle(one('x A 192.0.2.1'))
        self.assertNotIn('issues', result['zone'])
        self.assertIn('apex_soa_count',
                      {issue['code'] for issue in analyze(result['zone'])['issues']})

    def test_first_body_error_in_expansion_order_wins(self):
        with self.assertRaises(SourceError) as caught:
            compile_bundle(bundle({
                'main': '$INCLUDE a\n$INCLUDE b',
                'a': 'x A 192.0.2.1\ny A 192.0.2.999',
                'b': 'z A 192.0.2.998',
            }))
        position, = caught.exception.positions
        self.assertEqual(position['fragment'], 'a')
        self.assertEqual(position['line'], 2)

    def test_fragment_key_order_does_not_matter(self):
        first = compile_bundle(bundle({'main': '$INCLUDE a', 'a': 'x A 192.0.2.1',
                                       'b': ''}))
        second = compile_bundle({'origin': 'example.test.', 'default_ttl': 3600,
                                 'entry': 'main',
                                 'fragments': {'b': '', 'a': 'x A 192.0.2.1',
                                               'main': '$INCLUDE a'}})
        self.assertEqual(first, second)


if __name__ == '__main__':
    unittest.main()
