"""Frozen synthetic navigation mechanisms, not human gold or ranking quality.

Run ``python -m evals.navigation_structure`` to produce a reproducible JSON
report. The fixture is validated before the implementation is called; unknown
fields, changed expectations and incomplete cases cannot become passing input.
"""
from __future__ import annotations

import argparse
from collections import deque
from copy import deepcopy
import hashlib
import inspect
import json
import math
from pathlib import Path, PurePosixPath
from typing import Callable

from codesentry.core.symbol import FileMeta, Symbol
from codesentry.index.builder import IndexResult
from codesentry.index.entrypoint import EntryPoint
from codesentry.index.roles import RoleLabel

FIXTURE = Path(__file__).parent / 'fixtures' / 'navigation_structure_v1.json'
FROZEN_SHA256 = 'df5abc099133c50fa939609b42e929fb66582af03c343c83a97c5d9cefd4ee21'
CASE_KEYS = {'id', 'notes', 'files', 'entries', 'dependencies', 'file_pr', 'symbols',
             'missing_nodes', 'parameters', 'expected'}
EXPECTED_KEYS = {'error', 'depths', 'roots', 'required', 'forbidden', 'before',
                 'label_contains', 'deterministic'}
ENTRY_KEYS = {'file', 'level', 'reason', 'out_degree', 'in_degree', 'kind',
              'confidence', 'line', 'evidence'}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _keys(value, keys: set[str], where: str) -> None:
    _require(isinstance(value, dict) and set(value) == keys,
             f'{where}: missing or unknown fields')


def _path(value) -> str:
    _require(isinstance(value, str) and bool(value) and '\\' not in value
             and ':' not in value and not value.startswith('/')
             and all(part not in {'', '.', '..'} for part in value.split('/'))
             and PurePosixPath(value).as_posix() == value, 'invalid synthetic path')
    return value


def _paths(value, where: str) -> set[str]:
    _require(isinstance(value, list), f'{where}: expected list')
    for item in value:
        _path(item)
    _require(len(value) == len(set(value)), f'{where}: duplicate paths')
    return set(value)


def _valid_budget(parameters: dict) -> bool:
    return (type(parameters['max_depth']) is int and parameters['max_depth'] >= 0
            and type(parameters['max_items']) is int and parameters['max_items'] > 0)


def _distances(case: dict, production: set[str]) -> dict[str, int]:
    roots = {entry['file'] for entry in case['entries']
             if entry['file'] in production and entry['kind'] in {'process', 'mount'}
             and entry['confidence'] in {'declared', 'static'}}
    depths = {root: 0 for root in roots}
    pending = deque(sorted(roots))
    limit = case['parameters']['max_depth']
    while pending:
        source = pending.popleft()
        if depths[source] >= limit:
            continue
        for target in sorted(case['dependencies'].get(source, [])):
            if target in production and target not in depths:
                depths[target] = depths[source] + 1
                pending.append(target)
    return {path: depths.get(path, -1) for path in production}


def validate_fixture(document: dict) -> None:
    _keys(document, {'schema_version', 'fixture_id', 'frozen_on', 'status', 'purpose', 'cases'}, 'fixture')
    _require(type(document['schema_version']) is int and document['schema_version'] == 1,
             'unsupported fixture schema')
    _require(document['fixture_id'] == 'navigation-structure-v1'
             and document['status'] == 'frozen_synthetic_structural_regression'
             and document['frozen_on'] == '2026-10-27', 'unknown fixture identity')
    _require(isinstance(document['purpose'], str) and 'not human gold' in document['purpose'],
             'fixture must state its evidence limits')
    cases = document['cases']
    _require(isinstance(cases, list) and bool(cases), 'fixture has no cases')
    ids = []
    for case in cases:
        _keys(case, CASE_KEYS, 'case')
        _require(isinstance(case['id'], str) and bool(case['id'])
                 and isinstance(case['notes'], str), 'invalid case identity')
        ids.append(case['id'])
        _keys(case['parameters'], {'max_depth', 'max_items'}, case['id'] + '.parameters')
        expected = case['expected']
        _keys(expected, EXPECTED_KEYS, case['id'] + '.expected')
        _require(type(expected['deterministic']) is bool, 'deterministic must be boolean')
        _require(expected['error'] in {None, 'ValueError'}, 'unknown expected exception')
        _require(_valid_budget(case['parameters']) == (expected['error'] is None),
                 'invalid budget must expect ValueError; valid budget cannot expect failure')
        _require(isinstance(case['files'], list), 'files must be explicit metadata')
        metas = []
        for item in case['files']:
            _keys(item, set(FileMeta.model_fields), 'file metadata')
            _path(item['path'])
            metas.append(FileMeta.model_validate_json(json.dumps(item), strict=True))
        names = {meta.path for meta in metas}
        _require(len(names) == len(metas), 'duplicate file metadata')
        production = {meta.path for meta in metas if meta.is_production}
        missing = _paths(case['missing_nodes'], 'missing_nodes')
        _require(not names & missing, 'a missing node cannot have file metadata')
        known = names | missing
        _require(isinstance(case['file_pr'], dict), 'file_pr must be a mapping')
        _require(set(case['file_pr']) <= known, 'unknown PageRank node')
        for score in case['file_pr'].values():
            _require(type(score) in {int, float} and math.isfinite(score) and score >= 0,
                     'invalid synthetic PageRank score')
        _require(isinstance(case['dependencies'], dict)
                 and set(case['dependencies']) <= known, 'unknown dependency source')
        for targets in case['dependencies'].values():
            _require(_paths(targets, 'dependency targets') <= known, 'unknown dependency target')
        _require(isinstance(case['entries'], list), 'entries must be explicit')
        for entry in case['entries']:
            _keys(entry, ENTRY_KEYS, 'entry')
            _require(entry['file'] in known and entry['level'] == 'app', 'unknown entry node/level')
            _require(entry['kind'] in {'process', 'mount', 'assembly', 'bridge', 'candidate'}
                     and entry['confidence'] in {'declared', 'static', 'heuristic'}, 'unknown entry classification')
            _require(isinstance(entry['reason'], str) and bool(entry['reason']), 'missing entry reason')
            for key in ('line', 'out_degree', 'in_degree'):
                _require(type(entry[key]) is int and entry[key] >= (1 if key == 'line' else 0),
                         'invalid entry numeric metadata')
            _require(isinstance(entry['evidence'], list) and bool(entry['evidence']), 'entry needs evidence')
            for evidence in entry['evidence']:
                _keys(evidence, {'file', 'line', 'kind'}, 'entry evidence')
                _require(evidence['file'] in known and type(evidence['line']) is int
                         and evidence['line'] > 0 and isinstance(evidence['kind'], str)
                         and bool(evidence['kind']), 'invalid entry evidence')
        _require(isinstance(case['symbols'], list), 'symbols must be explicit')
        for item in case['symbols']:
            _keys(item, set(Symbol.model_fields) | set(Symbol.model_computed_fields), 'symbol')
            symbol = Symbol.model_validate_json(json.dumps(item), strict=True)
            _require(symbol.file in names, 'unknown symbol source')
            _require(all(item[key] == getattr(symbol, key) for key in Symbol.model_computed_fields),
                     'symbol computed metadata does not match its source fields')
        required = _paths(expected['required'], 'required')
        forbidden = _paths(expected['forbidden'], 'forbidden')
        roots = _paths(expected['roots'], 'roots')
        _require(required == production and forbidden <= known and not required & forbidden,
                 'expected coverage must include every production file, and no forbidden one')
        _require(isinstance(expected['depths'], dict) and set(expected['depths']) == required,
                 'missing expected depths')
        _require(all(type(depth) is int and depth >= -1 for depth in expected['depths'].values()),
                 'invalid expected depth')
        _require(roots == {name for name, depth in expected['depths'].items() if depth == 0},
                 'root expectation differs from depth expectation')
        if expected['error'] is None:
            _require(expected['depths'] == _distances(case, production),
                     'expected depths differ from independent shortest-distance oracle')
        _require(isinstance(expected['before'], list), 'before must be a list')
        for pair in expected['before']:
            _require(isinstance(pair, list) and len(pair) == 2 and len(set(pair)) == 2
                     and set(pair) <= required, 'unknown order constraint')
        _require(isinstance(expected['label_contains'], dict)
                 and set(expected['label_contains']) <= required
                 and all(isinstance(label, str) and bool(label) for label in expected['label_contains'].values()),
                 'unknown label constraint')
    _require(len(ids) == len(set(ids)), 'duplicate case IDs')


def load_fixture(path: Path = FIXTURE, *, verify_frozen: bool = True) -> tuple[dict, str]:
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if verify_frozen:
        _require(digest == FROZEN_SHA256, 'fixture bytes differ from the frozen v1 SHA256')
    document = json.loads(raw.decode('utf-8'))
    validate_fixture(document)
    return document, digest


def build_case(case: dict, variant: int = 0) -> IndexResult:
    def permute(items):
        items = list(items)
        return list(reversed(items)) if variant == 1 else items[1:] + items[:1] if variant == 2 else items
    result = IndexResult(root='synthetic:' + case['id'])
    result.files = [FileMeta.model_validate(item) for item in permute(case['files'])]
    result.roles = {meta.path: RoleLabel('core', .2) for meta in result.files}
    result.file_pr = dict(permute(case['file_pr'].items()))
    result.dependencies = {source: set(permute(targets)) for source, targets in permute(case['dependencies'].items())}
    for source, targets in result.dependencies.items():
        for target in targets:
            result.dependents.setdefault(target, set()).add(source)
    result.symbols = [Symbol.model_validate(item) for item in permute(case['symbols'])]
    accepted = inspect.signature(EntryPoint).parameters
    for item in permute(case['entries']):
        entry = EntryPoint(**{key: deepcopy(value) for key, value in item.items() if key in accepted})
        for key, value in item.items():
            if key not in accepted:
                setattr(entry, key, deepcopy(value))
        result.entrypoints.append(entry)
    return result


def _check_output(case: dict, output) -> list[str]:
    errors = []
    if not isinstance(output, list) or any(not isinstance(item, (tuple, list)) or len(item) != 3
                                         or not isinstance(item[0], str) or not isinstance(item[1], str)
                                         or not item[1] or type(item[2]) is not int for item in output):
        return ['output is not a list of (path, nonempty label, integer depth)']
    paths = [item[0] for item in output]
    depths = {item[0]: item[2] for item in output}
    labels = {item[0]: item[1] for item in output}
    expected = case['expected']
    if len(paths) != len(set(paths)):
        errors.append('duplicate recommendation')
    if set(paths) != set(expected['required']):
        errors.append('production coverage differs: ' + json.dumps({'missing': sorted(set(expected['required']) - set(paths)), 'extra': sorted(set(paths) - set(expected['required']))}))
    for path, depth in expected['depths'].items():
        if depths.get(path) != depth:
            errors.append(f'{path}: expected depth {depth}, got {depths.get(path)}')
    if {path for path, depth in depths.items() if depth == 0} != set(expected['roots']):
        errors.append('only declared/static process or mount entries may be depth zero')
    for first, second in expected['before']:
        if first in paths and second in paths and paths.index(first) >= paths.index(second):
            errors.append(f'expected {first} before {second}')
    for path, label in expected['label_contains'].items():
        if label not in labels.get(path, ''):
            errors.append(f'{path}: missing required label {label}')
    return errors


def evaluate_fixture(path: Path = FIXTURE, *, reading_function: Callable | None = None,
                     implementation_sha256: str | None = None) -> dict:
    document, digest = load_fixture(path)
    if reading_function is None:
        from codesentry.output.reading_order import reading_order
        reading_function = reading_order
    if implementation_sha256 is None:
        source = inspect.getsourcefile(reading_function)
        implementation_sha256 = hashlib.sha256(Path(source).read_bytes()).hexdigest() if source else None
    reports = []
    for case in document['cases']:
        failures = []
        outputs = []
        variants = range(3) if case['expected']['deterministic'] else range(1)
        for variant in variants:
            try:
                output = reading_function(build_case(case, variant), **case['parameters'])
                if case['expected']['error']:
                    failures.append(f'variant {variant}: expected ValueError, received output')
                else:
                    failures.extend(f'variant {variant}: {error}' for error in _check_output(case, output))
                    outputs.append(output)
            except Exception as error:
                if case['expected']['error'] != type(error).__name__:
                    failures.append(f'variant {variant}: unexpected {type(error).__name__}: {str(error)[:300]}')
        if outputs and any(output != outputs[0] for output in outputs[1:]):
            failures.append('output changes when input container order is permuted')
        reports.append({'id': case['id'], 'passed': not failures, 'failures': failures,
                        'output': outputs[0] if outputs else None, 'input_permutations': len(variants)})
    passed = sum(case['passed'] for case in reports)
    return {'schema_version': 1, 'evaluation': 'synthetic structural regression',
            'human_gold': False, 'p_at_10_evidence': False, 'cross_project_acceptance': False,
            'held_out_evaluation': False, 'external_project_source_read': False,
            'fixture_id': document['fixture_id'], 'fixture_sha256': digest,
            'reading_order_implementation_sha256': implementation_sha256,
            'totals': {'cases': len(reports), 'passed': passed, 'failed': len(reports) - passed},
            'status': 'passed' if passed == len(reports) else 'failed', 'cases': reports}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, default=FIXTURE)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        report = evaluate_fixture(args.fixture)
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        print(json.dumps({'status': 'invalid_fixture', 'error': str(error),
                          'human_gold': False, 'p_at_10_evidence': False}, ensure_ascii=False))
        return 2
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered, end='')
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
