"""Independent frozen supplement for branch coverage, never P@10 evidence."""
from copy import deepcopy
import importlib
import json

import pytest

from evals.navigation_coverage import (
    FROZEN_SHA256, evaluate_fixture, load_fixture, main, validate_fixture,
)


def test_supplement_is_frozen_without_changing_original_structure_fixture():
    from evals.navigation_structure import FROZEN_SHA256 as original_digest
    from evals.navigation_structure import load_fixture as load_original
    fixture, digest = load_fixture()
    assert digest == FROZEN_SHA256
    assert len(fixture['cases']) == 9
    original, actual = load_original()
    assert actual == original_digest
    assert len(original['cases']) == 22


@pytest.mark.parametrize('mutation', [
    lambda data: data['cases'][0].pop('priority_window'),
    lambda data: data['cases'][0]['files'][0].pop('is_parsed'),
    lambda data: data['cases'][0]['priority_window'].update(unknown=[]),
    lambda data: data['cases'][0]['priority_window']['required'].append('unknown.py'),
    lambda data: data['cases'][0]['expected']['depths'].update({'factory.py': 0}),
    lambda data: data['cases'][0]['expected'].update(human_gold=True),
    lambda data: data.update(cases=[]),
])
def test_unknown_missing_or_invented_supplement_constraints_fail_closed(mutation):
    document, _ = load_fixture()
    document = deepcopy(document)
    mutation(document)
    with pytest.raises((ValueError, KeyError)):
        validate_fixture(document)


def test_frozen_supplement_passes_current_navigation():
    report = evaluate_fixture()
    assert report['totals'] == {'cases': 9, 'passed': 9, 'failed': 0}, report['cases']
    assert report['status'] == 'passed'
    assert report['human_gold'] is False
    assert report['p_at_10_evidence'] is False
    assert report['cross_project_acceptance'] is False
    assert all(case['input_permutations'] == 3 for case in report['cases'])


def test_evaluator_detects_priority_starvation_even_with_correct_depths():
    from evals.navigation_structure import _distances

    def starved(result, **parameters):
        fixture, _ = load_fixture()
        case = next(item for item in fixture['cases'] if result.root == 'synthetic:' + item['id'])
        depths = _distances(case, {meta.path for meta in result.files if meta.is_production})
        return [(path, 'synthetic', depths[path])
                for path in sorted(depths, key=lambda path: (depths[path] < 0, -result.file_pr[path], path))]

    report = evaluate_fixture(reading_function=starved, implementation_sha256='synthetic-starved')
    assert report['status'] == 'failed'
    assert any('priority window omits' in error for case in report['cases'] for error in case['failures'])


def test_cli_refuses_changed_supplement(tmp_path, capsys):
    document, _ = load_fixture()
    document['cases'].pop()
    source = tmp_path / 'changed.json'
    source.write_text(json.dumps(document), encoding='utf-8')
    assert main(['--fixture', str(source)]) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'invalid_fixture'


def test_cli_returns_nonzero_for_starved_or_invalid_output(monkeypatch, capsys):
    module = importlib.import_module('codesentry.output.reading_order')
    monkeypatch.setattr(module, 'reading_order', lambda *args, **kwargs: [])
    assert main([]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'failed'
    assert report['totals']['failed'] == 9
