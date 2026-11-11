"""Binding evidence must not be confused with names that happen to match."""
from pathlib import Path

from codesentry.core.policy import Policy
from codesentry.core.symbol import CallSite, Symbol, SymbolKind
from codesentry.index.builder import build_index
from codesentry.index.resolver import SymbolResolver
from codesentry.parsers.python_parser import PythonParser


def project(files):
    symbols, calls, imports = [], [], {}
    parser = PythonParser()
    for file, text in files.items():
        syms, cs, _, imps = parser.parse_with_meta(Path("nonexistent"), file, text)
        symbols.extend(syms)
        calls.extend(cs)
        imports[file] = imps
    resolver = SymbolResolver()
    resolver.build(symbols, imports, set(), list(files))
    return resolver, resolver.resolve_all(calls, set(), set())


def test_relative_import_alias_resolves_actual_export():
    _, calls = project({"pkg/main.py": "from .helper import original as alias\ndef run(): alias()",
                        "pkg/helper.py": "def original(): pass"})
    assert len(calls) == 1
    assert (calls[0].target, calls[0].resolution) == ("pkg/helper.py::original", "cross_file")
    assert calls[0].is_certain


def test_relative_parent_import_and_module_alias_resolve():
    _, calls = project({"pkg/sub/main.py": "from ..helper import original as alias\nimport pkg.helper as helper\ndef run():\n alias()\n helper.original()",
                        "pkg/helper.py": "def original(): pass"})
    assert all(call.target == "pkg/helper.py::original" and call.is_certain for call in calls)


def test_from_package_import_submodule_is_supported_without_name_guess():
    resolver, calls = project({"pkg/main.py": "from . import helper\ndef run(): helper.original()",
                              "pkg/helper.py": "def original(): pass"})
    assert calls[0].target == "pkg/helper.py::original"
    assert calls[0].is_certain
    assert ("pkg/main.py", "pkg/helper.py") in resolver.resolve_import_edges()


def test_unknown_object_member_never_resolves_to_local_or_global_method():
    _, calls = project({"a.py": "def save(): pass\nclass A:\n def save(self): pass\ndef run(obj): obj.save()",
                        "b.py": "def save(): pass"})
    assert calls[0].target is None
    assert calls[0].resolution == "unresolved"


def test_external_module_member_never_resolves_to_same_named_project_function():
    _, calls = project({"a.py": "import os\ndef save(): pass\ndef run(): os.save()"})
    assert calls[0].target is None
    assert calls[0].resolution == "external"


def test_parameter_and_assignment_shadow_module_definition_and_import():
    _, calls = project({"a.py": "from helper import f\ndef run(f): f()\ndef other():\n f = value\n f()",
                        "helper.py": "def f(): pass"})
    assert all(call.target is None and not call.is_certain for call in calls)


def test_local_nested_binding_is_resolved_without_class_namespace_leak():
    _, calls = project({"a.py": "def run():\n def work(): pass\n def inner(): work()\n inner()\nclass A:\n def work(self): pass\n def save(self): work()"})
    by_source = {call.source: call for call in calls}
    assert by_source["a.py::run.inner"].target == "a.py::run.work"
    assert by_source["a.py::run"].target == "a.py::run.inner"
    assert not by_source["a.py::A.save"].is_certain


def test_explicit_class_member_uses_full_qualified_target():
    _, calls = project({"a.py": "class A:\n def save(self): pass\nclass B:\n def save(self): pass\ndef run():\n A.save()\n B.save()"})
    assert [call.target for call in calls] == ["a.py::A.save", "a.py::B.save"]
    assert all(call.resolution == "local" for call in calls)


def test_multiple_redefinitions_stay_ambiguous():
    _, calls = project({"a.py": "def save(): return 1\ndef save(): return 2\ndef run(): save()"})
    assert calls[0].resolution == "ambiguous"
    assert calls[0].target is None
    assert len(calls[0].candidates) == 2


def test_global_unique_is_only_a_heuristic():
    _, calls = project({"main.py": "def run(): save()", "helper.py": "def save(): pass"})
    assert (calls[0].target, calls[0].resolution) == ("helper.py::save", "heuristic")
    assert not calls[0].is_certain


def test_multiple_same_directory_candidates_are_never_first_selected():
    files = {"pkg/main.py": "def run(): save()", "pkg/a.py": "def save(): pass", "pkg/b.py": "def save(): pass"}
    _, calls = project(files)
    _, reversed_calls = project(dict(reversed(list(files.items()))))
    assert calls[0].target is None and calls[0].resolution == "ambiguous"
    assert calls[0].candidates == reversed_calls[0].candidates


def test_one_same_directory_candidate_is_only_a_labelled_guess():
    _, calls = project({"pkg/main.py": "def run(): save()", "pkg/a.py": "def save(): pass", "other/b.py": "def save(): pass"})
    assert calls[0].target == "pkg/a.py::save"
    assert calls[0].resolution == "heuristic"
    assert not calls[0].is_certain


def test_import_paths_do_not_match_substrings_or_basename_collisions():
    resolver, calls = project({"main.py": "from helper import save\ndef run(): save()",
                              "unrelated/helper.py": "def save(): pass"})
    assert calls[0].target is None and not calls[0].is_certain
    assert not resolver.resolve_import_edges()


def test_import_edges_include_empty_modules_and_are_order_stable():
    resolver, _ = project({"pkg/main.py": "from . import empty", "pkg/empty.py": ""})
    assert resolver.resolve_import_edges() == [("pkg/main.py", "pkg/empty.py")]


def test_ambiguous_module_paths_do_not_create_certain_import_edges():
    resolver, calls = project({"main.py": "from helper import save\ndef run(): save()",
                              "helper.py": "def save(): pass", "helper/__init__.py": "def save(): pass"})
    assert calls[0].resolution == "ambiguous"
    assert calls[0].target is None
    assert not resolver.resolve_import_edges()


def test_local_definition_wins_over_builtin_name_classification():
    resolver, _ = project({"a.py": "def print(): pass\ndef run(): print()"})
    calls = resolver.resolve_all([CallSite(caller_qname="a.py::run", callee_name="print", file="a.py", line=2)], {"print"}, set())
    assert calls[0].target == "a.py::print"
    assert calls[0].resolution == "local"


def test_builder_excludes_heuristics_from_rank_and_certain_impact(tmp_path):
    (tmp_path / "main.py").write_text("def run(): save()", encoding="utf-8")
    (tmp_path / "helper.py").write_text("def save(): pass", encoding="utf-8")
    result = build_index(tmp_path, Policy(), use_cache=False)
    assert result.call_stats["heuristic"] == 1
    assert result.edges[0].target == "helper.py::save"
    assert result.dependencies == result.dependents == result.reverse_refs == {}
    assert result.in_degree == result.out_degree == {}
    assert result.file_pr["main.py"] == result.file_pr["helper.py"]
    assert result.symbol_pr["main.py::run"] == result.symbol_pr["helper.py::save"]


def test_builder_keeps_exact_import_binding_in_rank_and_impact(tmp_path):
    (tmp_path / "main.py").write_text("from helper import save\ndef run(): save()", encoding="utf-8")
    (tmp_path / "helper.py").write_text("def save(): pass", encoding="utf-8")
    result = build_index(tmp_path, Policy(), use_cache=False)
    assert result.call_stats["cross_file"] == 1
    assert result.dependencies["main.py"] == {"helper.py"}
    assert result.dependents["helper.py"] == {"main.py"}
    assert result.file_pr["helper.py"] > result.file_pr["main.py"]
    assert result.symbol_pr["helper.py::save"] > result.symbol_pr["main.py::run"]


import pytest


@pytest.mark.parametrize("source", [
    "def other(): pass\nclass A:\n def work(): pass\n work = other\ndef run(): A.work()",
    "def work(): pass\ndef run(value):\n match value:\n  case {'callback': work}:\n   work()",
    "def work(): pass\ndef run(value):\n match value:\n  case [*work]:\n   work()",
    "def work(): pass\ndef run(value):\n match value:\n  case {**work}:\n   work()",
    "def work(): pass\ndef run():\n return lambda: ((work := lambda: None), work())",
    "def work(): pass\nclass A:\n work()\n def work(): pass",
    "def work(): pass\nclass A:\n def work(): pass\n values = [work() for _ in range(1)]",
])
def test_python_explicit_rebinding_and_unmodelled_scope_never_become_certain(source):
    _, calls = project({"main.py": source})
    work_calls = [call for call in calls if call.target_name == "work"]
    assert work_calls
    assert all(not call.is_certain for call in work_calls)


def test_python_import_does_not_refer_to_exporter_definition_after_reassignment():
    _, calls = project({"main.py": "from helper import work\ndef run(): work()",
                        "helper.py": "def work(): pass\ndef other(): pass\nwork = other"})
    assert not calls[0].is_certain
    assert calls[0].target is None


def test_python_relative_import_cannot_clamp_path_above_project_root():
    resolver, calls = project({"pkg/main.py": "from ...helper import work\ndef run(): work()",
                              "helper.py": "def work(): pass"})
    assert not calls[0].is_certain
    assert calls[0].target is None
    assert not resolver.resolve_import_edges()


def test_python_syntax_failure_is_visible_and_is_not_a_successful_cached_empty_result(tmp_path, monkeypatch):
    from codesentry.index.cache import ParseCache
    from codesentry.parsers.python_parser import PythonParser
    path = tmp_path / "broken.py"
    path.write_text("def broken(:", encoding="utf-8")
    parser = PythonParser()
    assert not parser.parse_with_meta(path, "broken.py", path.read_text())[2].is_parsed
    assert not parser.file_meta(path, "broken.py", False, False, False).is_parsed
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache-root"))
    result = build_index(tmp_path, Policy(), use_cache=True)
    assert result.parse_failures == 1
    assert not result.files[0].is_parsed
    cache = ParseCache(tmp_path)
    cache.load()
    assert "broken.py" not in cache.entries


def test_python_valid_empty_file_remains_parsed_and_cacheable(tmp_path, monkeypatch):
    project = tmp_path / "source"
    project.mkdir()
    (project / "empty.py").write_text("", encoding="utf-8")
    # Application caches are separate from source. A cache inside the target
    # tree is intentionally disabled by the file-access boundary.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache-root"))
    result = build_index(project, Policy(), use_cache=True)
    assert result.parse_failures == 0
    assert result.files[0].is_parsed
    # Toolchain/schema context is part of cache identity. Verify reuse through
    # the same builder context, not a context-free ParseCache reader.
    again = build_index(project, Policy(), use_cache=True)
    assert again.files[0].is_parsed
    assert again.parse_failures == 0
    assert again.cache_stats["hits"] >= 1
