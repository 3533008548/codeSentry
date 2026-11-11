"""Real synthetic Git repositories; no target projects or source execution."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from codesentry.access import AccessDenied, AccessPolicy
from codesentry.review import changes
from codesentry.review.changes import ChangeLimits, analyze_changes


GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="trusted Git executable unavailable")


def git(root, *args, payload=None):
    env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    return subprocess.run([GIT, "-c", "core.autocrlf=false", "-c", "core.hooksPath=" + os.devnull,
        "-c", "user.name=CodeSentry Test", "-c", "user.email=test@example.invalid", *args],
        cwd=root, env=env, input=payload, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    (root / "a.py").write_text("value = 1\n", encoding="utf-8", newline="\n")
    (root / "main.py").write_text("import a\n", encoding="utf-8", newline="\n")
    git(root, "add", ".")
    git(root, "commit", "-m", "synthetic baseline")
    return root


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def primary(report):
    return [row for row in report["changes"] if row["layer"] in {"combined", "staged", "commit"}]


def test_working_tree_keeps_net_staged_unstaged_and_untracked_changes(repository):
    (repository / "a.py").write_text("value = 2\n", encoding="utf-8", newline="\n")
    git(repository, "add", "a.py")
    (repository / "a.py").write_text("value = 3\n", encoding="utf-8", newline="\n")
    (repository / "new.py").write_text("import a\n", encoding="utf-8", newline="\n")
    index_before = (repository / ".git" / "index").read_bytes()
    report = analyze_changes(AccessPolicy(repository))
    assert report["change_status"] == "report_only", report["issues"]
    assert report["comparison"] == "working_tree" and report["target_sha"] is None
    assert report["summary"] == {"changed_files": 2, "staged": 1, "unstaged": 1, "untracked": 1, "affected_files": 3}
    assert report["source_sha256"]["a.py"] == sha("value = 3\n")
    assert report["impact"]["before"]["dependents"] == ["main.py"]
    assert report["impact"]["after"]["dependents"] == ["main.py"]
    assert (repository / ".git" / "index").read_bytes() == index_before
    assert report["gate_status"] == "not_evaluated" and not report["formal_acceptance"]["passed"]
    assert not report["coverage"]["whole_repository_evaluated"]
    assert "source" not in report and "content" not in str(report.keys())


def test_staged_hashes_are_index_evidence_not_current_working_tree(repository, monkeypatch):
    (repository / "a.py").write_text("value = 2\n", encoding="utf-8", newline="\n")
    git(repository, "add", "a.py")
    (repository / "a.py").write_text("value = 3\n", encoding="utf-8", newline="\n")
    access = AccessPolicy(repository)
    monkeypatch.setattr(access, "read_bytes", lambda *args, **kwargs: pytest.fail("staged comparison read worktree source"))
    report = analyze_changes(access, comparison="staged")
    assert report["change_status"] == "report_only", report["issues"]
    assert report["source_sha256"]["a.py"] == sha("value = 2\n")
    assert {row["layer"] for row in report["changes"]} == {"staged"}


def test_commit_comparison_pins_two_commits_without_merge_base_or_worktree_content(repository):
    before = git(repository, "rev-parse", "HEAD").decode().strip()
    (repository / "a.py").write_text("value = 2\n", encoding="utf-8", newline="\n")
    git(repository, "add", "a.py")
    git(repository, "commit", "-m", "synthetic target")
    after = git(repository, "rev-parse", "HEAD").decode().strip()
    (repository / "a.py").write_text("value = 99\n", encoding="utf-8", newline="\n")
    report = analyze_changes(AccessPolicy(repository), base_ref=before, comparison="commit", target_ref=after)
    assert report["base_sha"] == before and report["target_sha"] == after
    assert report["change_status"] == "report_only", report["issues"]
    assert report["source_sha256"]["a.py"] == sha("value = 2\n")
    assert not report["merge_base_evaluated"]


def test_deleted_file_propagates_through_before_graph(repository):
    (repository / "entry.py").write_text("import main\n", encoding="utf-8", newline="\n")
    git(repository, "add", "entry.py")
    git(repository, "commit", "-m", "synthetic importer")
    git(repository, "rm", "a.py")
    report = analyze_changes(AccessPolicy(repository))
    assert any(row["old_path"] == "a.py" and row["new_path"] is None and row["status"] == "deleted" for row in report["changes"])
    assert report["impact"]["before"]["dependents"] == ["entry.py", "main.py"]
    assert "a.py" not in report["source_sha256"]
    assert any(issue["status"] == "local_import_unresolved" and issue["side"] == "after" for issue in report["issues"])


def test_rename_is_preserved_as_delete_and_add_without_similarity_reads(repository):
    (repository / "a.py").rename(repository / "renamed.py")
    git(repository, "add", "-A")
    report = analyze_changes(AccessPolicy(repository))
    net = [row for row in report["changes"] if row["layer"] == "combined"]
    assert {(row["status"], row["old_path"], row["new_path"]) for row in net} == {
        ("deleted", "a.py", None), ("added", None, "renamed.py")}
    assert report["rename_detection"] == "not_performed_delete_add_preserved"


def test_permission_filter_applies_before_any_historical_blob_request(repository, monkeypatch):
    (repository / "private.py").write_text("private_value = 'synthetic-only'\n", encoding="utf-8", newline="\n")
    git(repository, "add", "private.py")
    git(repository, "commit", "-m", "synthetic denied file")
    forbidden = git(repository, "rev-parse", "HEAD:private.py").decode().strip()
    access = AccessPolicy(repository, {"exclude": ["private.py"]})
    original_process, original_read = changes._bounded_process, access.read_bytes
    requests = []

    def process(argv, **kwargs):
        requests.append((argv, kwargs.get("payload") or b""))
        return original_process(argv, **kwargs)

    def read(path, *args, **kwargs):
        assert path != "private.py"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(changes, "_bounded_process", process)
    monkeypatch.setattr(access, "read_bytes", read)
    report = analyze_changes(access)
    assert report["coverage"]["permissions_limited"] and report["coverage"]["excluded_paths"] >= 1
    assert "private.py" not in report["source_sha256"]
    assert all(forbidden.encode() not in payload for _, payload in requests)
    assert all("diff" not in argv and "status" not in argv and not any("find-renames" in arg for arg in argv) for argv, _ in requests)


def test_configuration_change_conservatively_affects_all_permitted_paths(repository):
    (repository / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8", newline="\n")
    (repository / "README.md").write_text("Synthetic documentation\n", encoding="utf-8", newline="\n")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "synthetic configuration")
    (repository / "pyproject.toml").write_text("[project]\nname='changed'\n", encoding="utf-8", newline="\n")
    report = analyze_changes(AccessPolicy(repository))
    assert report["impact"]["configuration_changed"]
    assert report["impact"]["dependents"] == ["README.md", "a.py", "main.py"]


def test_other_language_and_parse_failure_remain_incomplete(repository):
    (repository / "broken.py").write_text("def broken(:\n", encoding="utf-8", newline="\n")
    (repository / "ui.ts").write_text("throw new Error('never executed');\n", encoding="utf-8", newline="\n")
    report = analyze_changes(AccessPolicy(repository))
    assert report["change_status"] == "incomplete"
    assert {issue["status"] for issue in report["issues"]} >= {"python_parse_incomplete", "changed_language_not_evaluated"}
    assert report["impact"]["call_analysis"] == "not_evaluated"


@pytest.mark.parametrize("reference", ["--help", "HEAD~1", "HEAD:private.py", "main", "$(anything)"])
def test_unsupported_reference_never_reaches_git_or_falls_back(repository, monkeypatch, reference):
    monkeypatch.setattr(changes, "_bounded_process", lambda *args, **kwargs: pytest.fail("unsafe reference reached Git"))
    report = analyze_changes(AccessPolicy(repository), base_ref=reference)
    assert report["change_status"] == "unavailable" and report["base_sha"] is None
    assert report["changes"] == []


def test_missing_commit_does_not_fallback_to_head(repository):
    report = analyze_changes(AccessPolicy(repository), base_ref="f" * 40)
    assert report["change_status"] == "unavailable" and report["base_sha"] is None
    assert report["changes"] == [] and report["source_sha256"] == {}


@pytest.mark.parametrize("marker", ["shallow", "commondir", "objects/info/alternates", "objects/info/http-alternates"])
def test_shallow_linked_and_alternate_metadata_is_refused_before_git(repository, monkeypatch, marker):
    target = repository / ".git" / marker
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("synthetic unsupported metadata\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(changes, "_bounded_process", lambda *args, **kwargs: pytest.fail("unsupported repository reached Git"))
    report = analyze_changes(AccessPolicy(repository))
    assert report["change_status"] == "unavailable" and not report["changes"]


def test_original_git_config_and_inherited_git_options_are_not_used(repository, tmp_path, monkeypatch):
    # Any command reading the original config would fail on this invalid include.
    with (repository / ".git" / "config").open("a", encoding="utf-8", newline="\n") as stream:
        stream.write('\n[include]\npath = "' + str(tmp_path / "invalid-config").replace("\\", "/") + '"\n')
    (tmp_path / "invalid-config").write_text("[not valid\n", encoding="utf-8", newline="\n")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "untrusted-program")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "bad inherited options")
    original = changes._bounded_process

    def process(argv, **kwargs):
        env = kwargs["env"]
        assert "GIT_EXTERNAL_DIFF" not in env and "GIT_CONFIG_PARAMETERS" not in env
        assert env["GIT_CONFIG_GLOBAL"] == os.devnull and env["GIT_CONFIG_SYSTEM"] == os.devnull
        assert env["GIT_NO_LAZY_FETCH"] == "1"
        assert str(repository / ".git") not in [arg.removeprefix("--git-dir=") for arg in argv if arg.startswith("--git-dir=")]
        return original(argv, **kwargs)

    monkeypatch.setattr(changes, "_bounded_process", process)
    report = analyze_changes(AccessPolicy(repository))
    assert report["change_status"] == "report_only", report["issues"]


def test_object_reparse_or_alias_is_not_followed(repository, monkeypatch):
    original = changes.is_link
    objects = repository / ".git" / "objects"
    monkeypatch.setattr(changes, "is_link", lambda path: path == objects or original(path))
    monkeypatch.setattr(changes, "_bounded_process", lambda *args, **kwargs: pytest.fail("redirected objects reached Git"))
    assert analyze_changes(AccessPolicy(repository))["change_status"] == "unavailable"


def test_invalid_utf8_tree_name_is_not_decoded_or_given_a_blob_read():
    issues = []
    tree = b"100644 blob " + b"a" * 40 + b"\tbad-\xff.py\0"
    assert changes._parse_inventory(tree, index=False, issues=issues) == {}
    assert issues == [{"file": ".", "status": "invalid_git_path", "message": "Git 名称或元数据编码无法安全解析。"}]


@pytest.mark.parametrize("name", [b"folder\\private.py", b"../private.py", b"/private.py", b"C:/private.py"])
def test_git_literal_path_cannot_be_normalized_into_a_different_authorized_file(name):
    issues = []
    tree = b"100644 blob " + b"a" * 40 + b"\t" + name + b"\0"
    assert changes._parse_inventory(tree, index=False, issues=issues) == {}
    assert issues[0]["file"] == "." and issues[0]["status"] == "invalid_git_path"


def test_excluded_index_conflict_is_not_exposed_or_counted_as_in_scope_failure(repository):
    (repository / "private.py").write_text("synthetic_private = 1\n", encoding="utf-8", newline="\n")
    git(repository, "add", "private.py")
    git(repository, "commit", "-m", "synthetic private file")
    oid = git(repository, "rev-parse", "HEAD:private.py").decode().strip()
    git(repository, "update-index", "--force-remove", "private.py")
    payload = "".join(f"100644 {oid} {stage}\tprivate.py\n" for stage in (1, 2, 3)).encode("ascii")
    git(repository, "update-index", "--index-info", payload=payload)
    report = analyze_changes(AccessPolicy(repository, {"exclude": ["private.py"]}))
    assert report["change_status"] == "report_only", report["issues"]
    assert report["coverage"]["permissions_limited"]
    assert all(issue["file"] != "private.py" for issue in report["issues"])


def test_file_budget_marks_incomplete_instead_of_silently_complete(repository):
    report = analyze_changes(AccessPolicy(repository), limits=ChangeLimits(max_files=1))
    assert report["change_status"] == "incomplete" and not report["coverage"]["within_scope_complete"]
    assert any(issue["status"] == "file_budget_exhausted" for issue in report["issues"])


def test_live_permission_revocation_aborts_instead_of_returning_cached_changes(repository):
    access = AccessPolicy(repository)
    access.read_guard = lambda: (_ for _ in ()).throw(AccessDenied("scope revoked"))
    with pytest.raises(AccessDenied):
        analyze_changes(access)


def test_package_imports_are_resolved_by_exact_module_path_without_call_guesses(repository):
    (repository / "pkg").mkdir()
    (repository / "pkg" / "__init__.py").write_text("", encoding="utf-8", newline="\n")
    (repository / "pkg" / "leaf.py").write_text("value = 1\n", encoding="utf-8", newline="\n")
    (repository / "pkg" / "user.py").write_text("from .leaf import value\n", encoding="utf-8", newline="\n")
    (repository / "entry.py").write_text("import pkg.user\n", encoding="utf-8", newline="\n")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "synthetic package")
    (repository / "pkg" / "leaf.py").write_text("value = 2\n", encoding="utf-8", newline="\n")
    report = analyze_changes(AccessPolicy(repository))
    assert report["impact"]["before"]["dependents"] == ["entry.py", "pkg/user.py"]
    assert report["impact"]["after"]["dependents"] == ["entry.py", "pkg/user.py"]


@pytest.mark.parametrize("statement", ["from pkg import leaf\n", "from . import leaf\n"])
def test_from_import_known_submodule_is_included_in_both_graphs(repository, statement):
    (repository / "pkg").mkdir()
    (repository / "pkg" / "__init__.py").write_text("", encoding="utf-8", newline="\n")
    (repository / "pkg" / "leaf.py").write_text("value = 1\n", encoding="utf-8", newline="\n")
    source = repository / "entry.py" if statement.startswith("from pkg") else repository / "pkg" / "entry.py"
    source.write_text(statement, encoding="utf-8", newline="\n")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "synthetic from submodule")
    (repository / "pkg" / "leaf.py").write_text("value = 2\n", encoding="utf-8", newline="\n")
    report = analyze_changes(AccessPolicy(repository))
    relative = source.relative_to(repository).as_posix()
    assert relative in report["impact"]["before"]["dependents"]
    assert relative in report["impact"]["after"]["dependents"]


def test_from_import_member_submodule_ambiguity_is_conservative_and_incomplete(repository):
    (repository / "pkg").mkdir()
    (repository / "pkg" / "__init__.py").write_text("leaf = 'package member'\n", encoding="utf-8", newline="\n")
    (repository / "pkg" / "leaf.py").write_text("value = 1\n", encoding="utf-8", newline="\n")
    (repository / "entry.py").write_text("from pkg import leaf\n", encoding="utf-8", newline="\n")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "synthetic ambiguous member")
    (repository / "pkg" / "leaf.py").write_text("value = 2\n", encoding="utf-8", newline="\n")
    report = analyze_changes(AccessPolicy(repository))
    assert "entry.py" in report["impact"]["before"]["dependents"]
    assert report["change_status"] == "incomplete"
    assert any(issue["status"] == "from_import_binding_unknown" for issue in report["issues"])


def test_deleted_from_import_submodule_retains_before_impact_and_after_unknown(repository):
    (repository / "pkg").mkdir()
    (repository / "pkg" / "__init__.py").write_text("", encoding="utf-8", newline="\n")
    (repository / "pkg" / "leaf.py").write_text("value = 1\n", encoding="utf-8", newline="\n")
    (repository / "entry.py").write_text("from pkg import leaf\n", encoding="utf-8", newline="\n")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "synthetic removable submodule")
    git(repository, "rm", "pkg/leaf.py")
    report = analyze_changes(AccessPolicy(repository))
    assert "entry.py" in report["impact"]["before"]["dependents"]
    assert report["change_status"] == "incomplete"
    assert any(issue["status"] == "from_import_binding_unknown" and issue["side"] == "after" for issue in report["issues"])


def test_explicit_trusted_git_works_when_worker_path_is_cleaned(repository, monkeypatch):
    monkeypatch.setattr(changes.shutil, "which", lambda name: None)
    report = analyze_changes(AccessPolicy(repository), git_executable=Path(GIT))
    assert report["change_status"] == "report_only", report["issues"]


@pytest.mark.parametrize("kind", ["relative", "directory", "project_file", "missing"])
def test_untrusted_or_non_executable_git_parameter_is_not_launched(repository, tmp_path, monkeypatch, kind):
    if kind == "relative":
        selected = Path("git")
    elif kind == "directory":
        selected = tmp_path
    elif kind == "project_file":
        selected = repository / "git.exe"
        selected.write_bytes(b"synthetic non-tool")
    else:
        selected = tmp_path / "missing.exe"
    monkeypatch.setattr(changes, "_bounded_process", lambda *args, **kwargs: pytest.fail("invalid explicit tool launched"))
    report = analyze_changes(AccessPolicy(repository), git_executable=selected)
    assert report["change_status"] == "unavailable" and not report["changes"]


@pytest.mark.parametrize("limits", [{"max_files": True}, {"max_seconds": float("inf")}, {"max_file_bytes": 9*1024*1024}])
def test_invalid_limits_are_rejected(limits):
    with pytest.raises(ValueError):
        ChangeLimits(**limits)
