"""Synthetic graph contracts are frozen and fail closed before scoring."""
from copy import deepcopy
import importlib
import json

import pytest

from evals.navigation_structure import (
    FROZEN_SHA256, evaluate_fixture, load_fixture, main, validate_fixture,
)


def test_fixture_is_frozen_explicit_synthetic_evidence():
    fixture, digest = load_fixture()
    assert digest == FROZEN_SHA256
    assert len(fixture['cases']) == 22
    assert 'not human gold' in fixture['purpose']


@pytest.mark.parametrize('mutation', [
    lambda data: data['cases'][0]['files'][0].pop('is_test'),
    lambda data: data['cases'][0]['expected'].update(human_gold=True),
    lambda data: data['cases'][0]['file_pr'].update(unknown_source=1),
    lambda data: data['cases'][0]['expected']['depths'].update({'b.py': 3}),
    lambda data: data['cases'][0]['expected'].update(error='RuntimeError'),
    lambda data: data.update(cases=[]),
])
def test_missing_unknown_or_self_invented_expectations_are_not_passes(mutation):
    document, _ = load_fixture()
    document = deepcopy(document)
    mutation(document)
    with pytest.raises(ValueError):
        validate_fixture(document)


def test_declared_missing_node_remains_a_negative_not_a_production_file():
    document, _ = load_fixture()
    case = next(item for item in document['cases'] if item['missing_nodes'])
    assert case['missing_nodes'] == ['missing.py']
    assert 'missing.py' in case['expected']['forbidden']
    assert 'missing.py' not in case['expected']['required']


def test_frozen_cases_pass_against_current_navigation_implementation():
    report = evaluate_fixture()
    assert report['totals'] == {'cases': 22, 'passed': 22, 'failed': 0}, report['cases']
    assert report['status'] == 'passed'
    assert report['human_gold'] is False
    assert report['p_at_10_evidence'] is False
    assert report['cross_project_acceptance'] is False
    assert all(case['input_permutations'] == 3 for case in report['cases'])


def test_evaluator_records_missing_outputs_instead_of_treating_empty_as_success():
    report = evaluate_fixture(reading_function=lambda *args, **kwargs: [],
                              implementation_sha256='synthetic-broken-function')
    assert report['status'] == 'failed'
    assert report['totals']['failed'] > 0
    assert any('production coverage differs' in failure
               for case in report['cases'] for failure in case['failures'])


def test_cli_refuses_modified_fixture_before_reporting_results(tmp_path, capsys):
    document, _ = load_fixture()
    document['cases'].pop()
    source = tmp_path / 'changed.json'
    source.write_text(json.dumps(document), encoding='utf-8')
    assert main(['--fixture', str(source)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'invalid_fixture'
    assert report['p_at_10_evidence'] is False


def test_cli_returns_nonzero_for_navigation_failure(monkeypatch, capsys):
    module = importlib.import_module('codesentry.output.reading_order')
    monkeypatch.setattr(module, 'reading_order', lambda *args, **kwargs: [])
    assert main([]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'failed'
    assert report['totals']['failed'] > 0
