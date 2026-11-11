"""Static binding evidence: only parse fixture text, never import target code."""
from pathlib import Path

import pytest

from codesentry.index.resolver import SymbolResolver
from codesentry.parsers.python_parser import BUILTIN_NAMES, PythonParser


def analyse(files, legacy_builtins=frozenset(), legacy_helpers=frozenset()):
    symbols, calls, imports, kinds = [], [], {}, {}
    parser = PythonParser()
    metadata = {}
    for file, text in files.items():
        definitions, occurrences, meta, mapping = parser.parse_with_meta(Path("unread-fixture"), file, text)
        assert meta.is_parsed
        symbols.extend(definitions)
        calls.extend(occurrences)
        imports[file] = mapping
        kinds[file] = meta.import_kinds
        metadata[file] = meta
    resolver = SymbolResolver()
    resolver.build(symbols, imports, set(), list(files), import_kinds_by_file=kinds)
    return resolver, resolver.resolve_all(calls, set(legacy_builtins), set(legacy_helpers)), metadata


def test_common_method_or_helper_names_do_not_prove_global_bindings():
    _, calls, _ = analyse(
        {"main.py": "def run():\n get()\n start()\n assert_equal()"},
        {"get", "start"}, {"assert_equal"},
    )
    assert [call.resolution for call in calls] == ["unresolved"] * 3
    assert all(call.target is None for call in calls)
    assert not {"get", "start", "assert_equal"} & BUILTIN_NAMES


@pytest.mark.parametrize("name", ["get", "start", "print"])
def test_project_definitions_win_over_legacy_name_lists(name):
    _, calls, _ = analyse(
        {"main.py": f"def {name}(): pass\ndef run(): {name}()"},
        {name}, {name},
    )
    assert calls[0].target == f"main.py::{name}"
    assert calls[0].resolution == "local"


def test_actual_unshadowed_python_builtins_have_parser_evidence():
    _, calls, _ = analyse({"main.py": "def run():\n print('x')\n len([])"})
    assert [call.resolution for call in calls] == ["builtin", "builtin"]
    assert all(call.method == "unshadowed_python_builtin" for call in calls)


@pytest.mark.parametrize("source", [
    "def run(print): print()",
    "print = value\ndef run(): print()",
    "from missing import *\ndef run(): print()",
    "def print(): pass\ndef change():\n global print\n print = value\ndef run(): print()",
])
def test_shadowed_wildcard_or_global_rebound_name_is_not_builtin_or_certain(source):
    _, calls, _ = analyse({"main.py": source}, {"print"}, {"print"})
    print_calls = [call for call in calls if call.target_name == "print"]
    assert print_calls
    assert all(call.resolution not in {"builtin", "test_helper"} and not call.is_certain for call in print_calls)


def test_unknown_receiver_get_is_not_a_builtin_method():
    _, calls, _ = analyse({"main.py": "def run(obj): obj.get()"}, {"get"}, {"get"})
    assert calls[0].resolution == "unresolved"
    assert calls[0].target is None


def test_missing_third_party_module_is_not_external_without_evidence():
    resolver, calls, _ = analyse({"main.py": "import missing_package as dep\ndef run(): dep.work()"})
    assert calls[0].resolution == "unresolved"
    assert resolver.resolve_import_edges() == []
    assert resolver.import_records[0]["resolution"] == "unresolved"


def test_explicit_standard_library_origin_is_external_not_a_same_named_symbol():
    _, calls, _ = analyse({"main.py": "from os import getcwd\ndef run(): getcwd()", "other.py": "def getcwd(): pass"})
    assert calls[0].resolution == "external"
    assert calls[0].target is None


def test_import_package_does_not_prove_undeclared_child_module_access():
    resolver, calls, _ = analyse({
        "main.py": "import pkg\ndef run(): pkg.child.work()",
        "pkg/__init__.py": "",
        "pkg/child.py": "def work(): pass",
    })
    assert not calls[0].is_certain
    assert calls[0].target is None
    assert resolver.resolve_import_edges() == [("main.py", "pkg/__init__.py")]


def test_explicit_namespace_child_import_can_prove_its_member():
    _, calls, _ = analyse({
        "main.py": "import pkg.child\ndef run(): pkg.child.work()",
        "pkg/__init__.py": "",
        "pkg/child.py": "def work(): pass",
    })
    assert calls[0].target == "pkg/child.py::work"
    assert calls[0].is_certain


def test_package_initializer_attribute_does_not_guess_a_submodule():
    resolver, calls, _ = analyse({
        "pkg/main.py": "from . import helper\ndef run(): helper.work()",
        "pkg/__init__.py": "helper = value",
        "pkg/helper.py": "def work(): pass",
    })
    assert not calls[0].is_certain
    assert calls[0].target is None
    assert resolver.resolve_import_edges() == [("pkg/main.py", "pkg/__init__.py")]


@pytest.mark.parametrize("header,guard", [
    ("from typing import TYPE_CHECKING", "TYPE_CHECKING"),
    ("from typing import TYPE_CHECKING as CHECK", "CHECK"),
    ("import typing as types", "types.TYPE_CHECKING"),
])
def test_type_only_imports_are_categorized_without_runtime_call_claims(header, guard):
    resolver, calls, metadata = analyse({
        "main.py": f"{header}\nif {guard}:\n from helper import work\ndef run(): work()",
        "helper.py": "def work(): pass",
    })
    assert metadata["main.py"].import_kinds["helper"] == "type"
    assert not calls[0].is_certain
    assert ("main.py", "helper.py") in resolver.resolve_import_edges()
    record = next(item for item in resolver.import_records if item["module"] == "helper")
    assert (record["kind"], record["resolution"]) == ("type", "certain")


def test_same_spelling_without_typing_import_is_only_conditional():
    resolver, calls, metadata = analyse({
        "main.py": "TYPE_CHECKING = flag\nif TYPE_CHECKING:\n import helper\ndef run(): helper.work()",
        "helper.py": "def work(): pass",
    })
    assert metadata["main.py"].import_kinds["helper"] == "conditional"
    assert not calls[0].is_certain
    resolver.resolve_import_edges()
    assert resolver.import_records[0]["kind"] == "conditional"


def test_regular_conditional_import_cannot_become_a_certain_call_binding():
    resolver, calls, metadata = analyse({
        "main.py": "if feature:\n from helper import work\ndef run(): work()",
        "helper.py": "def work(): pass",
    })
    assert metadata["main.py"].import_kinds["helper"] == "conditional"
    assert not calls[0].is_certain
    resolver.resolve_import_edges()
    assert resolver.import_records[0]["kind"] == "conditional"


def test_decorated_or_conditional_definitions_do_not_prove_original_callable():
    _, calls, _ = analyse({"main.py": "def wrap(fn): return other\n@wrap\ndef work(): pass\nif feature:\n def start(): pass\ndef run():\n work()\n start()"})
    assert all(not call.is_certain for call in calls)


def test_definition_time_calls_belong_to_enclosing_execution_context():
    parser = PythonParser()
    _, calls, _, _ = parser.parse_with_meta(Path("unread-fixture"), "main.py", """
def outer():
    @decorate()
    def inner(value=default()):
        work()
    class Child(base()):
        body()
""")
    assert {call.callee_name: call.caller_qname for call in calls} == {
        "decorate": "main.py::outer", "default": "main.py::outer",
        "work": "main.py::outer.inner", "base": "main.py::outer", "body": "main.py::outer",
    }


def test_module_class_body_is_module_initialization_not_a_class_call():
    _, calls, _ = analyse({"main.py": "def work(): pass\nclass A:\n work()"})
    assert calls[0].source is None
    assert calls[0].target == "main.py::work"


def test_annotation_expressions_are_not_asserted_as_runtime_calls():
    _, calls, _ = analyse({"main.py": "def factory(): pass\ndef work(value: factory() = factory()) -> factory(): pass"})
    assert len(calls) == 3
    assert sum(call.is_certain for call in calls) == 1
    assert sum(call.method == "type_annotation_or_checking_context" for call in calls) == 2


def test_default_assignment_expression_invalidates_enclosing_name_binding():
    _, calls, _ = analyse({"main.py": "def work(): pass\ndef child(value=(work := replacement)): pass\ndef run(): work()"})
    assert not calls[0].is_certain


def test_python_metadata_reports_last_line_and_concrete_syntax_failure():
    parser = PythonParser()
    _, _, meta, _ = parser.parse_with_meta(Path("unread-fixture"), "main.py", "def work(): pass")
    assert meta.lines == 1
    _, _, broken, _ = parser.parse_with_meta(Path("unread-fixture"), "broken.py", "def broken(:")
    assert not broken.is_parsed
    assert broken.parse_error and "line 1" in broken.parse_error


def test_unreadable_missing_source_is_not_a_successful_empty_parse(tmp_path):
    meta = PythonParser().file_meta(tmp_path / "missing.py", "missing.py", False, False, False)
    assert not meta.is_parsed
    assert meta.parse_error.startswith("source_read_failed:")


@pytest.mark.parametrize("source", [
    "work()\nfrom helper import work",
    "def run():\n work()\n from helper import work",
    "def run():\n work()\n def work(): pass",
    "class A:\n work()\n from helper import work",
])
def test_same_execution_scope_cannot_call_a_later_import_or_definition(source):
    _, calls, _ = analyse({"main.py": source, "helper.py": "def work(): pass"})
    assert all(not call.is_certain for call in calls)


def test_declaration_order_uses_the_last_definition_of_a_name():
    _, calls, _, _ = PythonParser().parse_with_meta(Path("unread-fixture"), "main.py", """
work()
def work(): pass
work()
def work(): pass
work()
""")
    assert [call.binding_kind for call in calls] == ["shadowed", "shadowed", "local"]


@pytest.mark.parametrize("declaration, expression, expected_kind", [
    ("import os.path", "os.path.exists('x')", "namespace"),
    ("import os.path as tools", "tools.exists('x')", "namespace"),
    ("from os import path as tools", "tools.exists('x')", "symbol"),
])
def test_import_declaration_order_uses_the_bound_alias(declaration, expression, expected_kind):
    source = f"{expression}\n{declaration}\n{expression}"
    _, calls, _, _ = PythonParser().parse_with_meta(Path("unread-fixture"), "main.py", source)
    assert [call.binding_kind for call in calls] == ["shadowed", expected_kind]


def test_redefined_import_alias_does_not_retain_its_original_binding():
    _, calls, _ = analyse({
        "main.py": "from first import work as task\ntask()\nfrom second import work as task\ntask()",
        "first.py": "def work(): pass",
        "second.py": "def work(): pass",
    })
    assert all(call.target is None and not call.is_certain for call in calls)


def test_same_line_declaration_remains_conservative():
    _, calls, _, _ = PythonParser().parse_with_meta(
        Path("unread-fixture"), "main.py", "import os as tools; tools.getcwd()",
    )
    assert calls[0].binding_kind == "shadowed"


def test_closure_can_reference_a_later_outer_definition():
    _, calls, _ = analyse({"main.py": """
def outer():
    def inner():
        work()
    def work(): pass
    return inner()
"""})
    work_call = next(call for call in calls if call.target_name == "work")
    assert work_call.source == "main.py::outer.inner"
    assert work_call.target == "main.py::outer.work"
    assert work_call.is_certain


def test_decorator_and_default_use_enclosing_alias_but_body_parameter_shadows_it():
    _, calls, _, _ = PythonParser().parse_with_meta(Path("unread-fixture"), "main.py", """
from helper import work
@work()
def child(work=work()):
    work()
""")
    by_line = {call.line: call for call in calls}
    assert by_line[3].binding_kind == by_line[4].binding_kind == "symbol"
    assert by_line[3].module == by_line[4].module == "helper"
    assert by_line[3].caller_qname is by_line[4].caller_qname is None
    assert by_line[5].binding_kind == "shadowed"
    assert by_line[5].caller_qname == "main.py::child"



def test_legal_long_expression_is_visible_failure_not_parser_recursion_crash(tmp_path):
    # Approximately 8 KiB of valid flat expression syntax produces a very deep
    # left-associated AST. Parsing/analyzing it must not escape as RecursionError.
    text = "value = " + "+".join("1" for _ in range(4096))
    path = tmp_path / "deep.py"
    path.write_text(text, encoding="utf-8")
    parser = PythonParser()
    symbols, calls, meta, imports = parser.parse_with_meta(path, "deep.py", text)
    assert not meta.is_parsed
    assert meta.parse_error.startswith(("python_ast_resource_limit:", "python_ast_recursion_limit:"))
    assert symbols == calls == [] and imports == {}
    assert parser.parse(path, "deep.py") == ([], [])
    assert not parser.file_meta(path, "deep.py", False, False, False).is_parsed


def test_flat_large_tree_obeys_configured_node_budget():
    parser = PythonParser(max_ast_nodes=16)
    text = "\n".join(f"value_{number} = 1" for number in range(20))
    symbols, calls, meta, imports = parser.parse_with_meta(Path("unread-fixture"), "wide.py", text)
    assert not meta.is_parsed
    assert meta.parse_error == "python_ast_resource_limit: nodes>16"
    assert symbols == calls == [] and imports == {}


def test_configured_depth_budget_returns_explicit_diagnostic():
    parser = PythonParser(max_ast_depth=8)
    text = "value = " + "+".join("1" for _ in range(20))
    _, _, meta, _ = parser.parse_with_meta(Path("unread-fixture"), "deep.py", text)
    assert not meta.is_parsed
    assert meta.parse_error == "python_ast_resource_limit: depth>8"


def test_unexpected_analysis_recursion_is_reported_as_failed_parse(monkeypatch):
    parser = PythonParser()
    def overflow(*args):
        raise RecursionError("analysis exceeds interpreter stack")
    monkeypatch.setattr(parser, "_analyze", overflow)
    symbols, calls, meta, imports = parser.parse_with_meta(Path("unread-fixture"), "main.py", "def work(): pass")
    assert not meta.is_parsed
    assert meta.parse_error == "python_ast_recursion_limit: analysis"
    assert symbols == calls == [] and imports == {}


@pytest.mark.parametrize("limits", [
    {"max_ast_nodes": 0}, {"max_ast_depth": -1},
    {"max_ast_nodes": True}, {"max_ast_depth": 2.5},
])
def test_ast_resource_limits_require_positive_integers(limits):
    with pytest.raises(ValueError, match="positive integer"):
        PythonParser(**limits)
