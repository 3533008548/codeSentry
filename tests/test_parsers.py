"""Parser regressions: lexical identity, ownership and import/shadowing evidence."""
from pathlib import Path

import pytest

from codesentry.core.symbol import SymbolKind
from codesentry.parsers.python_parser import PythonParser
from codesentry.parsers.ts_parser import TypeScriptParser, _NODE_SCRIPT


def python_source(tmp_path: Path, text: str):
    path = tmp_path / "sample.py"
    path.write_text(text, encoding="utf-8")
    return PythonParser().parse_with_meta(path, "sample.py", text)


def test_python_same_method_names_and_nested_functions_keep_full_scope(tmp_path):
    symbols, calls, _, _ = python_source(tmp_path, """
class A:
    def save(self):
        def inner():
            work()
        inner()
class B:
    def save(self):
        other()
""")
    by_name = {symbol.qname: symbol for symbol in symbols}
    assert set(by_name) == {"sample.py::A", "sample.py::A.save", "sample.py::A.save.inner",
                            "sample.py::B", "sample.py::B.save"}
    assert by_name["sample.py::A.save.inner"].parent == "sample.py::A.save"
    assert by_name["sample.py::A.save.inner"].kind == SymbolKind.FUNCTION
    assert by_name["sample.py::B.save"].parent == "sample.py::B"
    assert {call.callee_name: call.caller_qname for call in calls} == {
        "work": "sample.py::A.save.inner", "inner": "sample.py::A.save", "other": "sample.py::B.save"}


def test_python_redefinitions_have_unique_location_independent_identity(tmp_path):
    text = "def save():\n    return 1\ndef save():\n    return 2\ndef same(): pass\ndef same(): pass\n"
    before, _, _, _ = python_source(tmp_path, text)
    after, _, _, _ = python_source(tmp_path, "\n\n" + text.replace("def save():", "def save():\n"))
    assert len({symbol.qname for symbol in before}) == 4
    assert [symbol.qname for symbol in before] == [symbol.qname for symbol in after]
    assert all("~" in symbol.qname for symbol in before)


def test_python_duplicate_parent_identity_propagates_to_children_and_calls(tmp_path):
    symbols, calls, _, _ = python_source(tmp_path, """
class A:
    def save(self): one()
class A:
    def save(self): two()
""")
    classes = [symbol for symbol in symbols if symbol.kind == SymbolKind.CLASS]
    methods = [symbol for symbol in symbols if symbol.kind == SymbolKind.METHOD]
    assert len(set(symbol.qname for symbol in symbols)) == 4
    assert {symbol.parent for symbol in methods} == {symbol.qname for symbol in classes}
    assert {call.caller_qname for call in calls} == {symbol.qname for symbol in methods}


def test_python_decorators_defaults_and_bases_use_enclosing_owner(tmp_path):
    _, calls, _, _ = python_source(tmp_path, """
def outer():
    @decorate()
    def inner(value=default()):
        work()
    class Child(base()):
        body()
""")
    assert {call.callee_name: call.caller_qname for call in calls} == {
        "decorate": "sample.py::outer", "default": "sample.py::outer",
        "work": "sample.py::outer.inner", "base": "sample.py::outer", "body": "sample.py::outer"}


def test_python_preserves_relative_import_alias_and_member_expression(tmp_path):
    _, calls, _, imports = python_source(tmp_path, """
from .helper import original as alias
import package.tool as toolkit
def run():
    alias()
    toolkit.save()
""")
    alias, member = calls
    assert (alias.module, alias.imported_name, alias.binding_kind) == (".helper", "original", "symbol")
    assert (member.module, member.receiver, member.expression) == ("package.tool", "toolkit", "toolkit.save")
    assert imports[".helper"] == {"original"}


def test_python_parameters_assignments_and_lambda_shadow_names(tmp_path):
    _, calls, _, _ = python_source(tmp_path, """
from helper import save
def run(save): save()
def other():
    save = factory()
    save()
def enclosing():
    return lambda save: save()
""")
    assert all(call.binding_kind == "shadowed" for call in calls if call.callee_name == "save")


@pytest.fixture
def ts_parser(tmp_path):
    # Tests use only the same pinned analyzer-owned toolchain as production.
    from codesentry.environment import get_toolchain
    toolchain = get_toolchain(tmp_path)
    if not toolchain.node or not toolchain.typescript_path:
        pytest.skip('managed TypeScript toolchain unavailable: ' + ', '.join(toolchain.diagnostics))
    parser = TypeScriptParser(tmp_path, toolchain=toolchain)
    yield parser
    parser.close()


def ts_source(parser, tmp_path, text):
    path = tmp_path / "sample.ts"
    path.write_text(text, encoding="utf-8")
    return parser.parse_with_meta(path, "sample.ts", text)


def test_ts_same_line_method_ownership_and_nested_functions(ts_parser, tmp_path):
    symbols, calls, _, _ = ts_source(ts_parser, tmp_path,
        "class A { save() { function inner() { work(); } inner(); } } "
        "class B { save() { other(); } }")
    by_qname = {symbol.qname: symbol for symbol in symbols}
    assert set(by_qname) == {"sample.ts::A", "sample.ts::A.save", "sample.ts::A.save.inner",
                             "sample.ts::B", "sample.ts::B.save"}
    assert by_qname["sample.ts::A.save.inner"].parent == "sample.ts::A.save"
    assert {call.callee_name: call.caller_qname for call in calls} == {
        "work": "sample.ts::A.save.inner", "inner": "sample.ts::A.save", "other": "sample.ts::B.save"}


def test_ts_overloads_and_duplicate_declarations_have_stable_unique_ids(ts_parser, tmp_path):
    text = "function f(x: string): string; function f(x: number): number; function f(x: any) { return x; }"
    before, _, _, _ = ts_source(ts_parser, tmp_path, text)
    after, _, _, _ = ts_source(ts_parser, tmp_path, "\n" + text.replace(";", ";\n"))
    assert len({symbol.qname for symbol in before}) == 3
    assert [symbol.qname for symbol in before] == [symbol.qname for symbol in after]


def test_ts_arrow_functions_keep_scope_and_shadowing(ts_parser, tmp_path):
    symbols, calls, _, _ = ts_source(ts_parser, tmp_path,
        "const run = (save: any) => { const inner = () => save(); inner(); };"
        "class A { save = () => work(); }")
    assert {symbol.qname for symbol in symbols} == {"sample.ts::run", "sample.ts::run.inner",
                                                   "sample.ts::A", "sample.ts::A.save"}
    assert next(call for call in calls if call.callee_name == "save").binding_kind == "shadowed"
    assert next(call for call in calls if call.callee_name == "work").caller_qname == "sample.ts::A.save"


def test_ts_import_alias_namespace_and_default_are_preserved(ts_parser, tmp_path):
    symbols, calls, _, imports = ts_source(ts_parser, tmp_path,
        'import { original as alias } from "./helper"; import * as toolkit from "./tool";'
        'import fallback from "./default"; export default function run() { alias(); toolkit.save(); fallback(); }')
    by_name = {call.callee_name: call for call in calls}
    assert (by_name["alias"].module, by_name["alias"].imported_name) == ("./helper", "original")
    assert by_name["save"].binding_kind == "namespace"
    assert by_name["fallback"].imported_name == "default"
    assert symbols[0].export_names == ["default"]
    assert imports["./helper"] == {"original"}


def test_node_script_checked_in_copy_matches_source():
    script = Path(__file__).parents[1] / "codesentry" / "parsers" / "_ts_extract.js"
    assert script.read_text(encoding="utf-8-sig").strip() == _NODE_SCRIPT.strip()


def test_ts_var_in_block_shadows_outer_function(ts_parser, tmp_path):
    _, calls, _, _ = ts_source(ts_parser, tmp_path,
        "function save() {} function run() { if (true) { var save = value; } save(); }")
    assert calls[0].binding_kind == "shadowed"


def test_ts_block_bindings_do_not_capture_outer_calls(ts_parser, tmp_path):
    _, calls, _, _ = ts_source(ts_parser, tmp_path,
        "function save() {} function run() { { let save = value; save(); } save(); }")
    assert calls[0].binding_kind == "shadowed"
    assert calls[1].binding_target == "sample.ts::save"


def test_ts_cross_file_alias_namespace_default_and_shadowing(ts_parser, tmp_path):
    from codesentry.index.resolver import SymbolResolver
    sources = {
        "main.ts": 'import { original as alias } from "./helper"; import * as kit from "./helper";'
                   'import fallback from "./helper"; function run() { alias(); kit.original(); fallback(); }'
                   'function shadow(alias: any) { alias(); }',
        "helper.ts": 'export function original() {} export default function other() {}',
    }
    symbols, calls, imports = [], [], {}
    for name, source in sources.items():
        path = tmp_path / name
        path.write_text(source, encoding="utf-8")
        syms, cs, _, imps = ts_parser.parse_with_meta(path, name, source)
        symbols.extend(syms)
        calls.extend(cs)
        imports[name] = imps
    resolver = SymbolResolver()
    resolver.build(symbols, imports, set(), list(sources))
    edges = resolver.resolve_all(calls, set(), set())
    assert [edge.target for edge in edges] == ["helper.ts::original", "helper.ts::original", "helper.ts::other", None]
    assert all(edge.is_certain for edge in edges[:3])
    assert not edges[3].is_certain
    assert resolver.resolve_import_edges() == [("main.ts", "helper.ts")]


@pytest.mark.parametrize("source", [
    "export {}; function run(){ {const hidden=()=>{};} hidden(); }",
    "export {}; function run(){ {function hidden(){}} hidden(); }",
    "export {}; const value=class Hidden{}; Hidden();",
    "export {}; function run(other:any){function f(){} {f=other;} f();}",
    "export {}; const obj={hidden(){}}; hidden();",
    "export {}; function run(){for(let hidden=()=>{};false;){} hidden();}",
    "export {}; class A { static field = hidden(); static hidden() {} }",
])
def test_ts_scope_visibility_and_rebinding_never_become_certain(ts_parser, tmp_path, source):
    from codesentry.index.resolver import SymbolResolver
    symbols, calls, _, imports = ts_source(ts_parser, tmp_path, source)
    resolver = SymbolResolver()
    resolver.build(symbols, {"sample.ts": imports}, set())
    edges = resolver.resolve_all(calls, set(), set())
    assert edges
    assert all(not edge.is_certain for edge in edges)


def resolve_ts_sources(parser, tmp_path, sources):
    from codesentry.index.resolver import SymbolResolver
    symbols, calls, imports = [], [], {}
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        syms, cs, _, imps = parser.parse_with_meta(path, name, source)
        symbols.extend(syms)
        calls.extend(cs)
        imports[name] = imps
    resolver = SymbolResolver()
    resolver.build(symbols, imports, set(), list(sources))
    return resolver, resolver.resolve_all(calls, set(), set())


@pytest.mark.parametrize("helper", [
    "export {}; function hidden() {}",
    "export default function hidden() {}",
    "export function hidden() {} hidden = other;",
])
def test_ts_named_import_requires_live_explicit_named_export(ts_parser, tmp_path, helper):
    _, edges = resolve_ts_sources(ts_parser, tmp_path, {
        "main.ts": "import {hidden} from './helper'; hidden();", "helper.ts": helper})
    assert len(edges) == 1
    assert not edges[0].is_certain
    assert edges[0].target is None


def test_ts_ambiguous_module_files_cannot_be_disambiguated_by_symbol_name(ts_parser, tmp_path):
    resolver, edges = resolve_ts_sources(ts_parser, tmp_path, {
        "main.ts": "import {hidden} from './helper'; hidden();",
        "helper.ts": "export function other() {}",
        "helper/index.ts": "export function hidden() {}"})
    assert edges[0].resolution == "ambiguous"
    assert not edges[0].is_certain
    assert not resolver.resolve_import_edges()


def test_ts_namespace_import_does_not_implicitly_import_child_directories(ts_parser, tmp_path):
    _, edges = resolve_ts_sources(ts_parser, tmp_path, {
        "main.ts": "import * as kit from './helper'; kit.nested.hidden();",
        "helper.ts": "export {};", "helper/nested.ts": "export function hidden() {}"})
    assert not edges[0].is_certain
    assert edges[0].target is None


@pytest.mark.parametrize("statement", ["import type {hidden} from './helper';",
                                        "import {type hidden} from './helper';"])
def test_ts_type_only_import_is_not_a_runtime_value_binding(ts_parser, tmp_path, statement):
    _, edges = resolve_ts_sources(ts_parser, tmp_path, {
        "main.ts": statement + "hidden();", "helper.ts": "export function hidden() {}"})
    assert not edges[0].is_certain
    assert edges[0].target is None


def test_ts_explicit_export_alias_still_resolves(ts_parser, tmp_path):
    _, edges = resolve_ts_sources(ts_parser, tmp_path, {
        "main.ts": "import {renamed} from './helper'; renamed();",
        "helper.ts": "function original() {} export {original as renamed};"})
    assert edges[0].target == "helper.ts::original"
    assert edges[0].is_certain


def test_ts_syntax_failure_and_valid_empty_file_are_distinct(ts_parser, tmp_path):
    assert not ts_source(ts_parser, tmp_path, "function broken(:")[2].is_parsed
    assert ts_source(ts_parser, tmp_path, "")[2].is_parsed
