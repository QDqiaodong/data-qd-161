"""Offline redacted structural export of a single-zone snapshot.

Support staff sometimes need to verify the *shape* of a zone — how records
distribute across owners and types, and which names reference which —
without receiving the original domain names or record payloads.  This
module compiles the existing single-zone snapshot (``model.py`` fields,
validation and normalization, unchanged) into a structural data set for
support-ticket attachments: the apex, every record owner and every RDATA
name target becomes an opaque alias, and records collapse into
``(owner, type, targets)`` count groups.  The result is a structural data
set, not a loadable zone file, and it does not promise to hide what
structure or counts alone reveal.

Alias model: an alias is ``{"space": "zone"|"external", "path": [...]}``.
The normalized apex is the root of the ``zone`` space with an empty path;
in-zone names (the apex itself or its label-boundary descendants) extend
it one step per label, root to leaf.  External names live under a disjoint
``external`` root and encode their full name the same way.  Each step is a
positive integer assigned per parent in sorted label order, so within one
space equal paths mean equal normalized names and a proper path prefix
means a label-level strict ancestor.  A complete leading ``*`` label of a
record owner is kept as the literal string ``"*"`` in the final path step.
Aliases carry no meaning outside the snapshot that produced them; nothing
here maps them back to the original names.
"""
from .model import analyze as analyze_zone


def _label_path(name, origin):
    """Split a normalized name into ``(space, root-to-leaf label path)``.

    In-zone membership is decided on a full label boundary: the apex
    itself, or a name ending in ``.<apex>``.  Everything else is external
    and encodes its complete label sequence from the external root.
    """
    if name == origin:
        return 'zone', []
    if name.endswith('.' + origin):
        rest = name[:-(len(origin) + 1)]
        return 'zone', list(reversed(rest.split('.')))
    return 'external', list(reversed(name[:-1].split('.')))


def _aliases(names, origin):
    """Assign every name its alias as a pure function of the name set.

    Integer steps are allocated per space and parent path in sorted label
    order, so the export depends only on the normalized name set — never on
    record order or on how a name was spelled in the input.  The wildcard
    marker needs no integer and stays the literal ``"*"``.
    """
    label_paths = {name: _label_path(name, origin) for name in names}
    children = {}
    for space, labels in label_paths.values():
        for depth, label in enumerate(labels):
            if label != '*':
                children.setdefault((space, tuple(labels[:depth])), set()).add(label)
    numbers = {}
    for (space, parent), pool in children.items():
        for number, label in enumerate(sorted(pool), 1):
            numbers[(space, parent, label)] = number
    aliases = {}
    for name, (space, labels) in label_paths.items():
        path = []
        for depth, label in enumerate(labels):
            if label == '*':
                path.append('*')
            else:
                path.append(numbers[(space, tuple(labels[:depth]), label)])
        aliases[name] = {'space': space, 'path': path}
    return aliases


def _path_key(path):
    """Order path steps: ``"*"`` before any integer; proper prefixes first."""
    return tuple((0,) if step == '*' else (1, step) for step in path)


def _target_names(record):
    """Map one normalized record's structured RDATA names by role."""
    kind = record['type']
    data = record['data']
    if kind in ('NS', 'CNAME'):
        return {'target': data}
    if kind == 'MX':
        return {'exchange': data['exchange']}
    if kind == 'SOA':
        return {'mname': data['mname'], 'rname': data['rname']}
    return {}


def _targets_key(targets):
    """Order a targets mapping by role name, then ``(space, path)``."""
    return tuple((role, alias['space'], _path_key(alias['path']))
                 for role, alias in sorted(targets.items()))


def analyze(data):
    """Compile one single-zone snapshot into its redacted structure.

    ``data`` is the existing snapshot (strictly ``origin``, ``default_ttl``
    and ``records``); validation and normalization are exactly
    ``model.py``'s, and model findings never block the export.  The result
    is strictly ``{"names": [...], "groups": [...]}``: name entries carry
    ``{name, has_records}`` and group entries carry
    ``{owner, type, targets, count}``, both ordered as documented.
    """
    audit = analyze_zone(data)
    origin = audit['origin']
    records = audit['records']

    owners = {record['owner'] for record in records}
    names = {origin} | owners
    for record in records:
        names.update(_target_names(record).values())
    aliases = _aliases(names, origin)

    table = [{'name': aliases[name], 'has_records': name in owners}
             for name in names]
    table.sort(key=lambda entry: (entry['name']['space'],
                                  _path_key(entry['name']['path'])))

    groups = {}
    for record in records:
        owner = aliases[record['owner']]
        targets = {role: aliases[name]
                   for role, name in _target_names(record).items()}
        key = (owner['space'], tuple(owner['path']), record['type'],
               tuple((role, alias['space'], tuple(alias['path']))
                     for role, alias in sorted(targets.items())))
        group = groups.get(key)
        if group is None:
            group = groups[key] = {'owner': owner, 'type': record['type'],
                                   'targets': targets, 'count': 0}
        group['count'] += 1
    ordered = sorted(groups.values(),
                     key=lambda group: (group['owner']['space'],
                                        _path_key(group['owner']['path']),
                                        group['type'],
                                        _targets_key(group['targets'])))
    return {'names': table, 'groups': ordered}
