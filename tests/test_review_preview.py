"""Preview remains report-only under errors, privacy restrictions and drift."""
import json
from pathlib import Path

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.cli.main import main
from codesentry.core.finding import Finding
from codesentry.review import scan


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    root = tmp_path / 'project'
    root.mkdir()
    return root


def long_function(root, name='a.py'):
    (root / name).write_text('def compute():\n    first = 1\n    second = 2\n    return first + second\n', encoding='utf-8')


def preview(root, **kwargs):
    return scan.scan_preview(AccessPolicy(root), max_function_lines=2, **kwargs)


def test_measured_finding_is_policy_debt_without_gate_authority(project):
    long_function(project)
    result = preview(project)
    assert result['review_status'] == 'report_only'
    assert result['gate_status'] == 'not_evaluated'
    assert result['summary'] == {'policy_debt_findings': 1, 'behavior_bug_findings': 0, 'blocking_findings': 0}
    row = result['findings'][0]
    finding = row['finding']
    assert row['classification'] == 'policy_debt' and row['can_block'] is False
    assert finding['verified'] and finding['facts']['function_lines'] == 4
    assert finding['facts']['max_function_lines'] == 2
    assert finding['identity_digest'].startswith('v2:')
    assert not Finding.model_validate(finding).can_block()


def test_no_finding_is_a_completed_rule_application_not_gate_pass(project):
    (project / 'small.py').write_text('def small():\n    return 1\n', encoding='utf-8')
    result = preview(project)
    assert result['findings'] == []
    assert result['review_status'] == 'report_only' and result['gate_status'] == 'not_evaluated'
    assert result['formal_acceptance']['passed'] is False


def test_class_async_and_nested_scopes_are_separate(project):
    (project / 'nested.py').write_text('class Worker:\n    async def run(self):\n        def inner():\n            x = 1\n            return x\n        return inner()\n', encoding='utf-8')
    result = preview(project)
    symbols = {row['finding']['symbol'] for row in result['findings']}
    assert symbols == {'nested.py::Worker.run', 'nested.py::Worker.run.<locals>.inner'}
    assert result['gate_status'] == 'not_evaluated'


def test_duplicate_definitions_preserve_occurrences(project):
    body = 'def same():\n    x = 1\n    return x\n'
    (project / 'copies.py').write_text(body + body, encoding='utf-8')
    result = preview(project)
    findings = [row['finding'] for row in result['findings']]
    assert len(findings) == 2 and [row['occurrence'] for row in findings] == [1, 2]
    assert len({row['identity_digest'] for row in findings}) == 2


def test_privacy_exclusion_and_repository_config_are_not_opened(project, monkeypatch):
    long_function(project)
    (project / 'private.py').write_text('private sentinel', encoding='utf-8')
    (project / 'policy.yaml').write_text('arbitrary: config', encoding='utf-8')
    access = AccessPolicy(project, {'exclude': ['private.py']})
    original = Path.open
    def checked(path, *args, **kwargs):
        if path in {project / 'private.py', project / 'policy.yaml'}:
            pytest.fail('denied or unsupported project config was opened')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', checked)
    result = scan.scan_preview(access, max_function_lines=2)
    assert result['summary']['policy_debt_findings'] == 1
    assert result['coverage']['excluded_python'] == 1
    assert result['coverage']['permissions_limited']


def test_parse_failure_keeps_other_fresh_findings_and_is_incomplete(project):
    long_function(project)
    (project / 'broken.py').write_text('def broken(:\n', encoding='utf-8')
    result = preview(project)
    assert result['review_status'] == 'incomplete'
    assert result['summary']['policy_debt_findings'] == 1
    assert any(issue['status'] == 'syntax_error' for issue in result['issues'])


def test_deep_expression_is_incomplete_without_losing_other_findings(project):
    long_function(project)
    (project / 'deep.py').write_text('def deep():\n    return ' + '+'.join(['1'] * 1500) + '\n', encoding='utf-8')
    result = preview(project)
    assert result['review_status'] == 'incomplete'
    assert result['summary']['policy_debt_findings'] == 1
    assert any(issue['file'] == 'deep.py' and issue['status'] == 'input_or_rule_incomplete'
               for issue in result['issues'])


@pytest.mark.parametrize('empty', [True, False])
def test_empty_or_unsupported_scope_never_passes(project, empty):
    if not empty:
        (project / 'main.ts').write_text('export const x = 1;', encoding='utf-8')
    result = preview(project)
    assert result['review_status'] == 'not_applicable'
    assert not result['coverage']['within_scope_complete']
    assert result['gate_status'] == 'not_evaluated'


def test_file_budget_counts_failed_attempts(project):
    (project / 'a.py').write_text('def broken(:', encoding='utf-8')
    long_function(project, 'b.py')
    result = preview(project, limits=scan.PreviewLimits(max_files=1))
    assert result['coverage']['attempted_python'] == 1
    assert result['review_status'] == 'incomplete'
    assert any(issue['status'] == 'budget_exhausted' for issue in result['issues'])


def test_failed_load_keeps_reserved_bytes_charged(project, monkeypatch):
    (project / 'a.py').write_bytes(b'\xff')
    long_function(project, 'b.py')
    access = AccessPolicy(project)
    original = Path.open
    def checked(path, *args, **kwargs):
        if path == project / 'b.py':
            pytest.fail('byte budget was bypassed after a failed load')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', checked)
    result = scan.scan_preview(access, limits=scan.PreviewLimits(max_total_bytes=8, max_file_bytes=64))
    assert result['coverage']['bytes_accounted_for_budget'] == 8
    assert result['coverage']['attempted_python'] == 1
    assert result['review_status'] == 'incomplete'


@pytest.mark.parametrize('mutation', ['add', 'delete'])
def test_source_inventory_drift_is_incomplete(project, monkeypatch, mutation):
    long_function(project)
    if mutation == 'delete':
        long_function(project, 'b.py')
    original = scan.VerificationContext.evaluate
    changed = False
    def evaluate(context):
        nonlocal changed
        findings = original(context)
        if not changed:
            changed = True
            if mutation == 'add':
                long_function(project, 'late.py')
            else:
                (project / 'b.py').unlink()
        return findings
    monkeypatch.setattr(scan.VerificationContext, 'evaluate', evaluate)
    result = preview(project)
    assert result['review_status'] == 'incomplete'
    assert any(issue['status'] == 'source_inventory_changed' for issue in result['issues'])


def test_changed_evidence_drops_that_files_old_findings(project, monkeypatch):
    long_function(project)
    original = scan.VerificationContext.evaluate
    def evaluate(context):
        findings = original(context)
        (project / 'a.py').write_text('CHANGED=1\n', encoding='utf-8')
        return findings
    monkeypatch.setattr(scan.VerificationContext, 'evaluate', evaluate)
    result = preview(project)
    assert result['findings'] == [] and result['review_status'] == 'incomplete'
    assert 'a.py' not in result['source_sha256']


def test_scope_revocation_discards_the_entire_preview(project, monkeypatch):
    long_function(project)
    permitted = True
    def guard():
        if not permitted:
            raise AccessDenied('revoked')
    access = AccessPolicy(project, read_guard=guard)
    original = scan.VerificationContext.evaluate
    def evaluate(context):
        nonlocal permitted
        findings = original(context)
        permitted = False
        return findings
    monkeypatch.setattr(scan.VerificationContext, 'evaluate', evaluate)
    with pytest.raises(AccessDenied):
        scan.scan_preview(access, max_function_lines=2)


def test_drift_seen_during_eligibility_check_is_not_just_report_only_false(project, monkeypatch):
    long_function(project)
    original = Finding.can_block
    def changed(finding, context=None):
        (project / 'a.py').write_text('CHANGED_AFTER_SERIALIZATION=1\n', encoding='utf-8')
        return original(finding, context)
    monkeypatch.setattr(Finding, 'can_block', changed)
    result = preview(project)
    assert result['review_status'] == 'incomplete'
    assert not result['findings'] and 'a.py' not in result['source_sha256']


def test_cli_preview_has_distinct_non_gate_exit_status(project, capsys):
    long_function(project)
    assert main(['scan', str(project), '--preview', '--json', '--confirm-access', '--max-function-lines', '2']) == 3
    report = json.loads(capsys.readouterr().out)
    assert report['gate_status'] == 'not_evaluated'
    assert report['summary']['policy_debt_findings'] == 1


def test_cli_default_scan_stays_closed_and_unconfirmed_preview_cannot_read(project, capsys):
    long_function(project)
    assert main(['scan', str(project), '--json']) == 2
    assert json.loads(capsys.readouterr().out)['review_status'] == 'not_implemented'
    assert main(['scan', str(project), '--preview', '--json']) == 2
    assert '确认' in capsys.readouterr().err
