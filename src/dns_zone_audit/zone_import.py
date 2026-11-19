"""Offline zone text bundle importer.

Compile a locally maintained text bundle — one logical entry fragment plus
the raw text fragments it references — into the existing single-zone
snapshot of ``model.py``, keeping a full source position for every produced
record so audits can trace which include produced which record.  The text
dialect is an internal, deliberately restricted master-file-like format; it
is not RFC 1035 master-file compatible.  Nothing outside the bundle is
read, no DNS queries are performed and no server is changed.

Dialect summary: physical lines are split on LF or CRLF and numbered from
1; a trailing line ending adds no extra empty line and there is no line
continuation.  ASCII space and tab separate tokens and ``;`` outside quotes
opens a comment.  Directives (``$ORIGIN``, ``$TTL``, ``$INCLUDE``) and
record types are uppercase; an indented directive is still a directive.
Unindented record lines are ``OWNER [TTL] TYPE RDATA``; lines starting with
space or tab are ``[TTL] TYPE RDATA`` and reuse the most recent explicit
owner.  Only TXT payloads use double quotes, with ``\\"`` and ``\\\\`` as
the only escapes.

A referenced fragment inherits the caller's current origin, TTL and most
recent explicit owner (already absolutized); when the fragment returns, the
caller's three state items are restored unchanged.  A fragment may be
included again once it has returned — only a cycle in the *active* include
chain is an error — and expansion budgets count actual occurrences.
"""
import json
import re

from .common import ident, number, require
from .model import analyze as analyze_zone
from .model import dns_name

MAX_FRAGMENTS = 128
MAX_DEPTH = 16
MAX_LINES = 20000
MAX_RECORDS = 10000
TTL_MAX = 2147483647
SERIAL_MAX = 4294967295
PREFERENCE_MAX = 65535

_FRAGMENT_ID = re.compile(r'[A-Za-z0-9_-]{1,64}')
_DIGITS = re.compile(r'[0-9]+')
_TYPES = ('SOA', 'NS', 'A', 'AAAA', 'CNAME', 'MX', 'TXT')
_DIRECTIVES = ('$ORIGIN', '$TTL', '$INCLUDE')
_RDATA_ARITY = {'A': 1, 'AAAA': 1, 'NS': 1, 'CNAME': 1, 'MX': 2, 'SOA': 7, 'TXT': 1}


class SourceError(ValueError):
    """Bundle body error pinned to full source position(s).

    ``positions`` holds the involved ``{"fragment", "line",
    "include_chain"}`` objects; for a duplicate record they are the first
    occurrence and the reoccurrence, in that order.  The string form
    carries the same positions so CLI diagnostics show them unchanged.
    """

    def __init__(self, message, positions=()):
        self.positions = [
            {'fragment': position['fragment'], 'line': position['line'],
             'include_chain': [dict(step) for step in position['include_chain']]}
            for position in positions
        ]
        text = message
        if self.positions:
            text += ': ' + '; '.join(
                json.dumps(position, sort_keys=True) for position in self.positions)
        super().__init__(text)


def _position(fragment_id, lineno, chain):
    """Snapshot the full source position of one expanded physical line."""
    return {'fragment': fragment_id, 'line': lineno,
            'include_chain': [dict(step) for step in chain]}


def _lines(text):
    """Split fragment text into physical lines (LF or CRLF), 1-based.

    A final line ending does not produce an extra empty line; an empty
    fragment has no lines at all.  A lone CR is content, not a separator.
    """
    if text == '':
        return []
    parts = text.split('\n')
    if parts[-1] == '':
        parts.pop()
    return [part[:-1] if part.endswith('\r') else part for part in parts]


def _tokenize(line, position):
    """Split one physical line into ``(text, quoted)`` tokens.

    Space and tab separate tokens; ``;`` outside quotes opens a comment.
    Double quotes are recognized here so comments and escapes behave
    uniformly; a later stage rejects quoted tokens outside TXT data.
    """
    tokens = []
    index = 0
    end = len(line)
    while index < end:
        char = line[index]
        if char in ' \t':
            index += 1
            continue
        if char == ';':
            break
        if char == '"':
            index += 1
            value = []
            closed = False
            while index < end:
                char = line[index]
                if char == '"':
                    closed = True
                    index += 1
                    break
                if char == '\\':
                    if index + 1 < end and line[index + 1] in '"\\':
                        value.append(line[index + 1])
                        index += 2
                        continue
                    raise SourceError('unsupported escape in quoted string', [position])
                value.append(char)
                index += 1
            if not closed:
                raise SourceError('unclosed quoted string', [position])
            if index < end and line[index] not in ' \t;':
                raise SourceError('quoted string must be followed by a separator', [position])
            tokens.append((''.join(value), True))
            continue
        start = index
        while index < end and line[index] not in ' \t;"':
            index += 1
        if index < end and line[index] == '"':
            raise SourceError('quote must start a token', [position])
        tokens.append((line[start:index], False))
    return tokens


def _number(token, maximum, position, what):
    """Parse an unsigned ASCII decimal token with the model's field bound."""
    if _DIGITS.fullmatch(token) is None:
        raise SourceError(what + ' must be an unsigned decimal number', [position])
    if len(token) > 10 or int(token) > maximum:
        raise SourceError(what + ' outside allowed bounds', [position])
    return int(token)


def _name(token, scope_origin, position, wildcard=False):
    """Resolve a relative/absolute name against the current scope origin."""
    try:
        return dns_name(token, scope_origin, wildcard=wildcard)
    except ValueError as error:
        raise SourceError(str(error), [position]) from error


class _Scope:
    """Per-expansion interpretation state: origin, TTL, recent owner.

    The recent owner is always kept absolutized, so a later ``$ORIGIN``
    change never rebinds it.  An included fragment receives a copy; the
    caller's own scope object is therefore restored unchanged on return.
    """

    __slots__ = ('origin', 'ttl', 'owner')

    def __init__(self, origin, ttl, owner):
        self.origin = origin
        self.ttl = ttl
        self.owner = owner

    def copy(self):
        return _Scope(self.origin, self.ttl, self.owner)


class _Bundle:
    """Shared expansion context: inputs, budgets and produced records."""

    def __init__(self, origin, default_ttl, fragments):
        self.origin = origin
        self.default_ttl = default_ttl
        self.fragments = fragments
        self.lines = 0
        self.records = []
        self.record_positions = []
        self.first_positions = {}


def _directive(bundle, fragment_id, lineno, chain, position, scope, name, args):
    if name not in _DIRECTIVES:
        raise SourceError('unknown directive: ' + name, [position])
    if len(args) != 1:
        raise SourceError(name + ' takes exactly one argument', [position])
    argument, quoted = args[0]
    if quoted:
        raise SourceError('quoted string is only valid as TXT data', [position])
    if name == '$ORIGIN':
        new_origin = _name(argument, scope.origin, position)
        if new_origin != bundle.origin and not new_origin.endswith('.' + bundle.origin):
            raise SourceError('$ORIGIN target outside zone', [position])
        scope.origin = new_origin
    elif name == '$TTL':
        scope.ttl = _number(argument, TTL_MAX, position, '$TTL argument')
    else:
        _include(bundle, fragment_id, lineno, chain, position, scope, argument)


def _include(bundle, fragment_id, lineno, chain, position, scope, target):
    if target not in bundle.fragments:
        raise SourceError('unknown fragment: ' + target, [position])
    active = {step['fragment'] for step in chain}
    active.add(fragment_id)
    if target in active:
        raise SourceError('include cycle: ' + target, [position])
    if len(chain) + 2 > MAX_DEPTH:
        raise SourceError('include depth exceeded', [position])
    _expand(bundle, target, scope.copy(),
            chain + [{'fragment': fragment_id, 'line': lineno}])


def _rdata(kind, fields, scope, position):
    if len(fields) != _RDATA_ARITY[kind]:
        raise SourceError(kind + ' takes exactly %d RDATA field(s)' % _RDATA_ARITY[kind],
                          [position])
    if kind == 'TXT':
        text, quoted = fields[0]
        if not quoted:
            raise SourceError('TXT data must be a quoted string', [position])
        return text
    for text, quoted in fields:
        if quoted:
            raise SourceError('quoted string is only valid as TXT data', [position])
    bare = [text for text, quoted in fields]
    if kind in ('A', 'AAAA'):
        return bare[0]
    if kind in ('NS', 'CNAME'):
        return _name(bare[0], scope.origin, position)
    if kind == 'MX':
        return {'preference': _number(bare[0], PREFERENCE_MAX, position, 'MX preference'),
                'exchange': _name(bare[1], scope.origin, position)}
    # SOA: mname rname serial refresh retry expire minimum
    return {'mname': _name(bare[0], scope.origin, position),
            'rname': _name(bare[1], scope.origin, position),
            'serial': _number(bare[2], SERIAL_MAX, position, 'SOA serial'),
            'refresh': _number(bare[3], TTL_MAX, position, 'SOA refresh'),
            'retry': _number(bare[4], TTL_MAX, position, 'SOA retry'),
            'expire': _number(bare[5], TTL_MAX, position, 'SOA expire'),
            'minimum': _number(bare[6], TTL_MAX, position, 'SOA minimum')}


def _record(bundle, position, scope, indented, tokens):
    index = 0
    if indented:
        if scope.owner is None:
            raise SourceError('record without owner: no previous explicit owner', [position])
        owner = scope.owner
    else:
        text, quoted = tokens[0]
        if quoted:
            raise SourceError('quoted string is only valid as TXT data', [position])
        owner = _name(text, scope.origin, position, wildcard=True)
        scope.owner = owner
        index = 1
    rest = tokens[index:]
    ttl = None
    if rest and not rest[0][1] and _DIGITS.fullmatch(rest[0][0]) is not None:
        ttl = _number(rest[0][0], TTL_MAX, position, 'TTL')
        rest = rest[1:]
    if not rest:
        raise SourceError('record type required', [position])
    kind, quoted = rest[0]
    if quoted:
        raise SourceError('quoted string is only valid as TXT data', [position])
    if kind not in _TYPES:
        raise SourceError('unsupported record type: ' + kind, [position])
    record = {'owner': owner, 'type': kind,
              'ttl': scope.ttl if ttl is None else ttl,
              'data': _rdata(kind, rest[1:], scope, position)}
    _commit(bundle, position, record)


def _commit(bundle, position, record):
    """Budget-check, normalize and deduplicate one decoded record.

    Normalization reuses the unchanged single-zone model on a one-record
    snapshot, so every model validation is reported with this record's
    full source position.  Identity is the model's ``(owner, type,
    repr(RDATA))`` — TTL never participates — and a collision reports the
    first occurrence and the reoccurrence with both full positions.
    """
    if len(bundle.records) >= MAX_RECORDS:
        raise SourceError('record budget exceeded', [position])
    try:
        normalized = analyze_zone({'origin': bundle.origin,
                                   'default_ttl': bundle.default_ttl,
                                   'records': [record]})['records'][0]
    except ValueError as error:
        raise SourceError(str(error), [position]) from error
    identity = (normalized['owner'], normalized['type'], repr(normalized['data']))
    first = bundle.first_positions.get(identity)
    if first is not None:
        raise SourceError('duplicate DNS record (first occurrence, then reoccurrence)',
                          [first, position])
    bundle.first_positions[identity] = position
    bundle.records.append(normalized)
    bundle.record_positions.append(position)


def _expand(bundle, fragment_id, scope, chain):
    """Interpret one fragment body once, in depth-first expansion order.

    Every physical line of every occurrence counts against the expansion
    budget, including blank, comment and directive lines.  ``scope`` is
    private to this expansion; ``chain`` lists the include steps from the
    entry fragment down to this one.
    """
    for lineno, line in enumerate(_lines(bundle.fragments[fragment_id]), 1):
        bundle.lines += 1
        position = _position(fragment_id, lineno, chain)
        if bundle.lines > MAX_LINES:
            raise SourceError('expanded line budget exceeded', [position])
        tokens = _tokenize(line, position)
        if not tokens:
            continue
        head, head_quoted = tokens[0]
        if not head_quoted and head.startswith('$'):
            _directive(bundle, fragment_id, lineno, chain, position, scope,
                       head, tokens[1:])
        else:
            _record(bundle, position, scope, line[:1] in (' ', '\t'), tokens)


def compile_bundle(data):
    """Compile one text bundle into a single-zone snapshot plus sources.

    ``data`` is strictly ``{"origin", "default_ttl", "entry",
    "fragments"}``; every fragment id and text is validated even when the
    fragment is never referenced.  The result is ``{"zone", "sources"}``
    where ``zone`` (origin/default_ttl from the bundle header, records in
    the model's normalized list and order, TTLs materialized to integers)
    can be passed straight to ``model.analyze`` and ``sources[i]`` is the
    full source position of ``records[i]`` in that same order.  Model
    ``issues`` never fail the import.
    """
    require(data, 'origin default_ttl entry fragments')
    raw_origin = ident(data['origin'])
    origin = dns_name(raw_origin.rstrip('.') + '.', raw_origin.rstrip('.') + '.')
    default_ttl = number(data['default_ttl'], 0, TTL_MAX)
    fragments = data['fragments']
    if not isinstance(fragments, dict) or not 1 <= len(fragments) <= MAX_FRAGMENTS:
        raise ValueError('fragments must contain 1 to 128 fragments')
    for fragment_id, text in fragments.items():
        if not isinstance(fragment_id, str) or _FRAGMENT_ID.fullmatch(fragment_id) is None:
            raise ValueError('invalid fragment id: ' + repr(fragment_id))
        if not isinstance(text, str):
            raise ValueError('fragment text must be a string: ' + fragment_id)
    entry = data['entry']
    if not isinstance(entry, str) or entry not in fragments:
        raise ValueError('entry must name an existing fragment')

    bundle = _Bundle(origin, default_ttl, fragments)
    _expand(bundle, entry, _Scope(origin, default_ttl, None), [])

    audit = analyze_zone({'origin': origin, 'default_ttl': default_ttl,
                          'records': bundle.records})
    positions = {}
    for record, position in zip(bundle.records, bundle.record_positions):
        positions[(record['owner'], record['type'], repr(record['data']))] = position
    sources = [positions[(record['owner'], record['type'], repr(record['data']))]
               for record in audit['records']]
    return {'zone': {'origin': audit['origin'], 'default_ttl': default_ttl,
                     'records': audit['records']},
            'sources': sources}
