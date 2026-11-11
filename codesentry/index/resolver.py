"""Resolve lexical/import bindings separately from navigation-only guesses.

``local`` and ``cross_file`` represent static binding evidence. A unique name or
nearby directory is only a ``heuristic``; ambiguous candidates never select the
first file. Object member names alone do not establish a binding.
"""
from __future__ import annotations

import builtins
import posixpath
import sys
from types import BuiltinFunctionType
from collections import defaultdict
from dataclasses import dataclass, field

from codesentry.core.symbol import CallSite, Symbol, SymbolKind


@dataclass
class ResolvedCall:
    source: str | None
    target_name: str
    target: str | None
    file: str
    line: int
    resolution: str
    candidates: tuple[str, ...] = ()
    method: str = ""

    def __post_init__(self):
        self.candidates = tuple(self.candidates)

    @property
    def is_internal(self) -> bool:
        """A project candidate exists; this alone does not prove a binding."""
        return self.target is not None

    @property
    def is_certain(self) -> bool:
        return self.target is not None and self.resolution in {"local", "cross_file"}


@dataclass
class SymbolResolver:
    defs_by_file: dict[str, set[str]] = field(default_factory=dict)
    imports_by_file: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    imported_names: set[str] = field(default_factory=set)
    name_to_files: dict[str, list[str]] = field(default_factory=dict)
    qname_to_file: dict[str, str] = field(default_factory=dict)
    external_names: set[str] = field(default_factory=set)
    builtin_names: set[str] = field(default_factory=set)
    test_helper_names: set[str] = field(default_factory=set)
    import_kinds_by_file: dict[str, dict[str, str]] = field(default_factory=dict)
    import_records: list[dict] = field(default_factory=list)

    def build(
        self, symbols: list[Symbol],
        imports_by_file: dict[str, dict[str, set[str]]],
        imported_names: set[str], all_files: list[str] | None = None,
        import_kinds_by_file: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.defs_by_file = defaultdict(set)
        self.imports_by_file = imports_by_file
        self.imported_names = imported_names
        self.import_kinds_by_file = import_kinds_by_file or {}
        self.import_records = []
        self.name_to_files = defaultdict(list)
        self.qname_to_file = {}
        self._symbols = {symbol.qname: symbol for symbol in symbols}
        self._by_scope: dict[tuple[str, str | None, str], list[Symbol]] = defaultdict(list)
        self._by_name: dict[str, list[Symbol]] = defaultdict(list)
        self._all_files = sorted(set(all_files or []) | set(imports_by_file) | {s.file for s in symbols})
        for symbol in sorted(symbols, key=lambda item: item.qname):
            self.defs_by_file[symbol.file].add(symbol.name)
            self.qname_to_file[symbol.qname] = symbol.file
            self._by_scope[(symbol.file, symbol.parent, symbol.name)].append(symbol)
            self._by_name[symbol.name].append(symbol)
            if symbol.file not in self.name_to_files[symbol.name]:
                self.name_to_files[symbol.name].append(symbol.file)

    def _module_files(self, caller_file: str, module: str) -> list[str]:
        """Only exact project paths; no basename/substr/first-candidate match.

        Custom sys.path, TS aliases and re-export chains need environment or
        compiler binding evidence, so they remain unresolved here.
        """
        if not module or module.startswith("node:"):
            return []
        is_python = caller_file.endswith(".py")
        if is_python:
            dots = len(module) - len(module.lstrip("."))
            if dots:
                base = posixpath.dirname(caller_file)
                for _ in range(dots - 1):
                    if not base or base == ".":
                        return []
                    base = posixpath.dirname(base)
                target = posixpath.normpath(posixpath.join(base, module[dots:].replace(".", "/")))
            else:
                target = module.replace(".", "/")
            paths = {target + ".py", posixpath.join(target, "__init__.py")}
        else:
            if module.startswith("."):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(caller_file), module))
            else:
                # Package specifiers and tsconfig aliases are environment-dependent.
                return []
            root, ext = posixpath.splitext(target)
            if ext in {".js", ".jsx", ".mjs", ".cjs"}:
                target = root
            paths = {target, *(target + ext for ext in (".ts", ".tsx", ".mts", ".cts")),
                     *(posixpath.join(target, "index" + ext) for ext in (".ts", ".tsx"))}
        return [path for path in self._all_files if path in paths]

    def _members(self, parents: list[Symbol], parts: list[str]) -> list[Symbol]:
        parents = [symbol for symbol in parents if symbol.binding_is_static]
        for part in parts:
            parents = [member for parent in parents
                       for member in self._by_scope.get((parent.file, parent.qname, part), [])
                       if member.binding_is_static]
        return sorted(parents, key=lambda item: item.qname)

    def _lexical(self, call: CallSite, root: str) -> list[Symbol]:
        if call.binding_kind == "unbound":
            return []
        if call.binding_kind == "local":
            if call.binding_target in self._symbols:
                symbol = self._symbols[call.binding_target]
                return [symbol] if symbol.binding_is_static else []
            return [symbol for symbol in self._by_scope.get((call.file, call.binding_scope, root), [])
                    if symbol.binding_is_static]
        scope = self._symbols.get(call.caller_qname or "")
        while scope is not None:
            candidates = [symbol for symbol in self._by_scope.get((call.file, scope.qname, root), [])
                          if symbol.binding_is_static]
            if candidates and scope.kind != SymbolKind.CLASS:
                return candidates
            scope = self._symbols.get(scope.parent or "")
        return [symbol for symbol in self._by_scope.get((call.file, None, root), [])
                if symbol.binding_is_static]

    def _known_external(self, caller_file: str, module: str) -> bool:
        """An explicit standard-library origin, never an absent-name guess.

        This classifies the declared origin, not installation availability or
        runtime success. Custom loaders/search paths stay outside this resolver.
        """
        if module.startswith("node:"):
            return True
        if not module or module.startswith("."):
            return False
        if module in self.external_names:
            return True  # Reserved for trusted environment-supplied evidence.
        root = module.split(".", 1)[0]
        return (caller_file.endswith(".py") and root in sys.stdlib_module_names
                and not self._module_files(caller_file, root))

    def _missing_import_kind(self, caller_file: str, module: str) -> str:
        return "external" if self._known_external(caller_file, module) else "unresolved"

    def _imported(self, call: CallSite, parts: list[str]) -> tuple[list[Symbol], str]:
        if call.binding_kind == "namespace":
            members = parts[1:]
            if not members:
                return [], self._missing_import_kind(call.file, call.module)
            modules = [(call.module, members)]
            if call.file.endswith(".py"):
                # ``import pkg`` does not prove that pkg.child was imported.
                # Nested module paths need an explicit import occurrence.
                declared = self.imports_by_file.get(call.file, {})
                for split in range(1, len(members)):
                    module = call.module + "." + ".".join(members[:split])
                    if module in declared:
                        modules.append((module, members[split:]))
            result: list[Symbol] = []
            found_file = False
            for module, path in modules:
                files = self._module_files(call.file, module)
                found_file |= bool(files)
                if len(files) > 1:
                    return [], "ambiguous"
                roots = [symbol for file in files for symbol in self._by_scope.get((file, None, path[0]), [])
                         if symbol.binding_is_static and (call.file.endswith(".py") or path[0] in symbol.export_names)]
                result.extend(self._members(roots, path[1:]))
            return list({symbol.qname: symbol for symbol in result}.values()), (
                "unresolved" if found_file else self._missing_import_kind(call.file, call.module))
        files = self._module_files(call.file, call.module)
        if len(files) > 1:
            return [], "ambiguous"
        roots = [symbol for file in files for symbol in self._symbols.values()
                 if symbol.file == file and symbol.parent is None and symbol.binding_is_static
                 and ((call.file.endswith(".py") and symbol.name == call.imported_name)
                      or call.imported_name in symbol.export_names)]
        result = self._members(roots, parts[1:])
        if not result and not files and call.file.endswith(".py") and len(parts) > 1:
            # Namespace package from-imports can prove a submodule. If an
            # initializer exists, its unmodelled assignments/re-exports may
            # provide the attribute instead, so do not guess a submodule.
            sep = "" if call.module.endswith(".") else "."
            files = self._module_files(call.file, call.module + sep + call.imported_name)
            if len(files) > 1:
                return [], "ambiguous"
            roots = [symbol for file in files for symbol in self._by_scope.get((file, None, parts[1]), [])
                     if symbol.binding_is_static]
            result = self._members(roots, parts[2:])
        return result, "unresolved" if files else self._missing_import_kind(call.file, call.module)

    @staticmethod
    def _answer(candidates: list[Symbol], kind: str, method: str):
        names = tuple(sorted({symbol.qname for symbol in candidates}))
        if len(names) == 1:
            return names[0], kind, names, method
        return None, "ambiguous" if names else "unresolved", names, method

    def _resolve_call(self, call: CallSite):
        expression = call.expression or (f"{call.receiver}.{call.callee_name}" if call.receiver else call.callee_name)
        parts = expression.split(".")
        # Bracket/call/complex receivers require types or value analysis.
        if not all(part.replace("$", "_").isidentifier()
                   or (part.startswith("#") and part[1:].replace("$", "_").isidentifier())
                   for part in parts):
            return None, "unresolved", (), "dynamic_expression"
        if call.binding_kind == "type_only":
            return None, "unresolved", (), "type_annotation_or_checking_context"
        if call.binding_kind == "shadowed":
            return None, "unresolved", (), "local_value_or_parameter"
        if call.binding_kind in {"symbol", "namespace"}:
            candidates, missing = self._imported(call, parts)
            if candidates and any(symbol.kind in {SymbolKind.TYPE_ALIAS, SymbolKind.INTERFACE} for symbol in candidates):
                return None, "unresolved", (), "type_only_definition"
            if candidates:
                return self._answer(candidates, "cross_file", "exact_import")
            return None, missing, (), "exact_import_missing"
        roots = self._lexical(call, parts[0])
        if call.binding_kind == "local" and not roots:
            return None, "unresolved", (), "rebound_definition"
        if roots:
            if len(parts) > 1:
                # Only an explicitly bound class/namespace proves a static member.
                roots = [symbol for symbol in roots if symbol.kind in {SymbolKind.CLASS, SymbolKind.MODULE}]
            candidates = self._members(roots, parts[1:])
            if candidates and any(symbol.kind in {SymbolKind.TYPE_ALIAS, SymbolKind.INTERFACE} for symbol in candidates):
                return None, "unresolved", (), "type_only_definition"
            if candidates:
                return self._answer(candidates, "local", "lexical_binding")
            return None, "unresolved", (), "unknown_member"
        if call.receiver:
            return None, "unresolved", (), "unknown_receiver"
        # The parser must prove a bare Python builtin lookup after lexical
        # shadowing. A legacy allowlist (get/start/assert_*) is not evidence.
        value = vars(builtins).get(call.callee_name)
        if (call.file.endswith(".py") and call.binding_kind == "builtin"
                and isinstance(value, (BuiltinFunctionType, type))):
            return None, "builtin", (), "unshadowed_python_builtin"
        candidates = self._by_name.get(call.callee_name, [])
        if len(candidates) > 1:
            near = [symbol for symbol in candidates
                    if posixpath.dirname(symbol.file) == posixpath.dirname(call.file)]
            if len(near) == 1:
                return self._answer(near, "heuristic", "unique_same_directory")
            return None, "ambiguous", tuple(sorted(symbol.qname for symbol in candidates)), "name_candidates"
        if candidates:
            return self._answer(candidates, "heuristic", "global_unique_name")
        return None, "unresolved", (), "no_binding"

    def resolve(self, callee: str, caller_file: str) -> tuple[str | None, str]:
        """Compatibility API: no receiver or import alias evidence is inferred."""
        call = CallSite(caller_qname=None, callee_name=callee, file=caller_file, line=1)
        target, kind, _, _ = self._resolve_call(call)
        return target, kind

    def resolve_import_edges(self) -> list[tuple[str, str]]:
        """Return path-proven dependencies and retain their execution category.

        Type/conditional imports are dependencies for reading, not proof that a
        runtime import or call occurred. Ambiguous/unknown paths stay in records
        and never become edges via a filename or symbol-name fallback.
        """
        edges: set[tuple[str, str]] = set()
        self.import_records = []

        def record(caller: str, module: str, kind: str, files: list[str], evidence: str):
            target = files[0] if len(files) == 1 else None
            resolution = ("certain" if target else "ambiguous" if files else
                          self._missing_import_kind(caller, module))
            self.import_records.append({
                "source": caller, "target": target, "module": module,
                "kind": kind, "resolution": resolution,
                "candidates": sorted(files), "evidence": evidence,
            })
            if target and target != caller:
                edges.add((caller, target))

        for caller, imports in sorted(self.imports_by_file.items()):
            for module, names in sorted(imports.items()):
                kind = self.import_kinds_by_file.get(caller, {}).get(module, "unknown")
                # A local module called typing defeats the standard guard claim.
                if kind == "type" and self._module_files(caller, "typing"):
                    kind = "conditional"
                files = self._module_files(caller, module)
                record(caller, module, kind, files, "exact_module_path")
                if not files and caller.endswith(".py") and module.startswith("."):
                    # Only initializer-free namespace packages permit this small
                    # submodule rule. Initializer attributes remain unresolved.
                    sep = "" if module.endswith(".") else "."
                    for name in sorted(names):
                        if name == "*":
                            continue
                        submodule = module + sep + name
                        subfiles = self._module_files(caller, submodule)
                        if subfiles:
                            record(caller, submodule, kind, subfiles, "explicit_from_import_namespace_submodule")
        return sorted(edges)

    def resolve_all(self, calls: list[CallSite], builtin_names: set[str],
                    test_helper_names: set[str]) -> list[ResolvedCall]:
        self.builtin_names = builtin_names
        self.test_helper_names = test_helper_names
        out: list[ResolvedCall] = []
        for call in calls:
            target, kind, candidates, method = self._resolve_call(call)
            out.append(ResolvedCall(
                source=call.caller_qname, target_name=call.callee_name,
                target=target, file=call.file, line=call.line, resolution=kind,
                candidates=candidates, method=method,
            ))
        return out
