"""Frozen synthetic branch coverage checks; not ranking quality or human gold.

This supplements, and never changes, navigation_structure_v1. Universal file
coverage and true-distance checks are shared; the added assertions concern
which evidenced branches receive space in a sufficiently large reading window.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
from typing import Callable

from evals.navigation_structure import (
    CASE_KEYS, _check_output, _keys, _paths, _require, build_case,
    validate_fixture as _validate_structure_fixture,
)

FIXTURE = Path(__file__).parent / 'fixtures' / 'navigation_coverage_v1.json'
FROZEN_SHA256 = '593676c80210620c41d55d1f6fa3dad94dc7b82021ce1bb1bf8ebe87eec525ab'


def validate_fixture(document: dict) -> None:
    _keys(document, {'schema_version', 'fixture_id', 'frozen_on', 'status', 'purpose', 'cases'}, 'fixture')
    _require(type(document['schema_version']) is int and document['schema_version'] == 1,
             'unsupported supplemental fixture schema')
    _require(document['fixture_id'] == 'navigation-coverage-v1'
             and document['status'] == 'frozen_synthetic_structural_regression'
             and document['frozen_on'] == '2026-10-27', 'unknown supplemental fixture identity')
    _require(isinstance(document['purpose'], str) and 'not human gold' in document['purpose'],
             'supplement must state its evidence limits')
    _require(isinstance(document['cases'], list) and bool(document['cases']), 'supplement has no cases')
    universal = deepcopy(document)
    # Reuse only the v1 universal schema/oracle, without editing its fixture or
    # accepting another identity from an external caller.
    universal['fixture_id'] = 'navigation-structure-v1'
    for source, target in zip(document['cases'], universal['cases']):
        _keys(source, CASE_KEYS | {'priority_window'}, 'supplemental case')
        _keys(source['priority_window'], {'required', 'forbidden'}, 'priority_window')
        required = _paths(source['priority_window']['required'], 'priority required')
        forbidden = _paths(source['priority_window']['forbidden'], 'priority forbidden')
        production = set(source['expected']['required'])
        _require(required <= production and forbidden <= production and not required & forbidden,
                 'priority constraints must name disjoint production files')
        budget = source['parameters']['max_items']
        _require(type(budget) is int and len(required) <= budget,
                 'priority constraint cannot promise impossible window coverage')
        _require(source['expected']['error'] is None and source['expected']['deterministic'] is True,
                 'supplement requires valid deterministic cases')
        target.pop('priority_window')
    _validate_structure_fixture(universal)


def load_fixture(path: Path = FIXTURE, *, verify_frozen: bool = True) -> tuple[dict, str]:
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if verify_frozen:
        _require(digest == FROZEN_SHA256, 'fixture bytes differ from the frozen coverage v1 SHA256')
    document = json.loads(raw.decode('utf-8'))
    validate_fixture(document)
    return document, digest


def _check_priority(case: dict, output: list) -> list[str]:
    if not isinstance(output, list) or any(not isinstance(item, (tuple, list)) or len(item) != 3 for item in output):
        return []  # The universal output checker already rejects this shape.
    window = {item[0] for item in output[:case['parameters']['max_items']]}
    errors = []
    for path in case['priority_window']['required']:
        if path not in window:
            errors.append(f'priority window omits required evidenced branch file {path}')
    for path in case['priority_window']['forbidden']:
        if path in window:
            errors.append(f'priority window promotes ineligible structural hint {path}')
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
        for variant in range(3):
            try:
                output = reading_function(build_case(case, variant), **case['parameters'])
                failures.extend(f'variant {variant}: {error}' for error in _check_output(case, output))
                failures.extend(f'variant {variant}: {error}' for error in _check_priority(case, output))
                outputs.append(output)
            except Exception as error:
                failures.append(f'variant {variant}: unexpected {type(error).__name__}: {str(error)[:300]}')
        if outputs and any(output != outputs[0] for output in outputs[1:]):
            failures.append('output changes when input container order is permuted')
        reports.append({'id': case['id'], 'passed': not failures, 'failures': failures,
                        'output': outputs[0] if outputs else None, 'input_permutations': 3})
    passed = sum(case['passed'] for case in reports)
    return {'schema_version': 1, 'evaluation': 'synthetic structural regression',
            'supplement': 'evidenced branch priority-window coverage',
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
