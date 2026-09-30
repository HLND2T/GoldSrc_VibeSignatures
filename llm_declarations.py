"""Validate literal preprocessor declarations without importing or executing scripts.

This accepts a deliberately bounded Python grammar, not arbitrary Python dataflow.
Dependency fields belong to the declaration; selection and runtime-only values go
through select_llm_specs. Forwarding helpers use the llm_decompile_specs parameter.
"""

from __future__ import annotations

import ast
from pathlib import PurePosixPath
from string import Formatter

from llm_spec import LLM_SPEC_OPTIONAL_KEYS, LLM_SPEC_REQUIRED_KEYS, normalize_llm_decompile_specs

DECLARATION = "LLM_DECOMPILE"


class DeclarationError(ValueError):
    pass


def _fail(path, node, message):
    raise DeclarationError(f"{path}:{getattr(node, 'lineno', 1)}: {message}")


def _path_template(value, root, suffix, path, node, field):
    relative = PurePosixPath(value)
    if (
        "\\" in value
        or relative.is_absolute()
        or ".." in relative.parts
        or not value.startswith(root + "/")
        or not value.endswith(suffix)
    ):
        _fail(path, node, f"{field}: unsafe or invalid path {value!r}")
    try:
        for _, name, spec, conversion in Formatter().parse(value):
            if name is not None and (
                name not in {"gamever", "platform", "module_name", "module"} or spec or conversion
            ):
                raise ValueError(f"unsupported placeholder {name!r}")
        remainder = value
        for name in ("gamever", "platform", "module_name", "module"):
            remainder = remainder.replace("{" + name + "}", "")
        if "{" in remainder or "}" in remainder:
            raise ValueError("escaped or unmatched braces are not supported")
    except ValueError as exc:
        _fail(path, node, f"{field}: {exc}")


def declaration_specs(declaration):
    if isinstance(declaration, dict):
        return [spec for branch in declaration.values() for spec in branch]
    return declaration or []


def parse_declaration(source: str, path: str, *, check_usage: bool = True):
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        raise DeclarationError(f"{path}:{exc.lineno}: {exc.msg}") from exc
    assignments = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Name) and n.id == DECLARATION and isinstance(n.ctx, (ast.Store, ast.Del))
    ]
    declarations = [
        n
        for n in tree.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == DECLARATION
    ]
    if assignments and (len(assignments) != 1 or len(declarations) != 1):
        _fail(path, assignments[0], "LLM_DECOMPILE requires exactly one unconditional module-level assignment")
    for child in ast.walk(tree):
        if isinstance(child, ast.arg) and child.arg == DECLARATION:
            _fail(path, child, "LLM_DECOMPILE must not be shadowed by a parameter")
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == DECLARATION:
            _fail(path, child, "LLM_DECOMPILE must be a literal assignment")
        if isinstance(child, (ast.Import, ast.ImportFrom)) and any(
            (alias.asname or alias.name) == DECLARATION for alias in child.names
        ):
            _fail(path, child, "LLM_DECOMPILE must be declared locally, not imported")
    declaration = None
    if declarations:
        node = declarations[0]
        for child in ast.walk(node.value):
            if isinstance(child, ast.Dict):
                keys = []
                for key in child.keys:
                    if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                        _fail(
                            path,
                            child,
                            "LLM_DECOMPILE requires literal string dictionary keys; unpacking is unsupported",
                        )
                    if key.value in keys:
                        _fail(path, key, f"LLM_DECOMPILE duplicate key {key.value!r}")
                    keys.append(key.value)
        try:
            declaration = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError) as exc:
            _fail(path, node, f"LLM_DECOMPILE must contain only literal values ({exc})")
        branches = declaration if isinstance(declaration, dict) else {"default": declaration}
        if not branches:
            _fail(path, node, "LLM_DECOMPILE must not be empty")
        for name, specs in branches.items():
            if not isinstance(name, str) or not name or not isinstance(specs, list) or not specs:
                _fail(path, node, f"LLM_DECOMPILE[{name!r}] requires a nonempty list of specs")
            branch_node = node.value
            if isinstance(branch_node, ast.Dict):
                branch_node = next(
                    value for key, value in zip(branch_node.keys, branch_node.values) if key.value == name
                )
            seen_symbols = set()
            for index, spec in enumerate(specs):
                spec_node = branch_node.elts[index]
                prefix = f"LLM_DECOMPILE[{name!r}][{index}]"
                if not isinstance(spec, dict):
                    _fail(path, spec_node, f"{prefix}: requires a spec dictionary")
                missing = LLM_SPEC_REQUIRED_KEYS - spec.keys()
                unknown = spec.keys() - (LLM_SPEC_REQUIRED_KEYS | LLM_SPEC_OPTIONAL_KEYS)
                if missing or unknown:
                    _fail(
                        path, spec_node, f"{prefix}: missing fields {sorted(missing)}, unknown fields {sorted(unknown)}"
                    )
                try:
                    valid = normalize_llm_decompile_specs([spec])
                except (TypeError, ValueError):
                    valid = None
                if valid is None:
                    _fail(path, spec_node, f"{prefix}: invalid spec field types or values: {spec!r}")
                if spec["symbol_name"] in seen_symbols:
                    _fail(path, spec_node, f"{prefix}.symbol_name: duplicate {spec['symbol_name']!r}")
                seen_symbols.add(spec["symbol_name"])
                _path_template(spec["prompt_path"], "prompt", ".md", path, spec_node, prefix + ".prompt_path")
                for reference in spec["reference_yaml_paths"]:
                    _path_template(reference, "references", ".yaml", path, spec_node, prefix + ".reference_yaml_paths")
                for policy in spec["dependency_policy"]:
                    _path_template(
                        "references/" + policy, "references", ".yaml", path, spec_node, prefix + ".dependency_policy"
                    )
    if check_usage:
        _validate_usage(tree, declarations[0] if declarations else None, path)
    return declaration


def _validate_usage(tree, declaration, path):
    """Accept direct selections, scoped aliases, literal kwargs and explicit forwarding.

    This is an authoring contract, not a sandbox or a proof of arbitrary Python.
    Dynamic reflection and arbitrary user-defined spec producers are unsupported.
    """
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    declaration_nodes = set(ast.walk(declaration)) if declaration else set()

    def scope(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return node
        return tree

    bindings = {}
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imports[(scope(node), alias.asname or alias.name)] = (node.module or "") + "." + alias.name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports[(scope(node), alias.asname or alias.name)] = alias.name
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings.setdefault((scope(node), node.name), []).append(node)
        if isinstance(node, ast.arg):
            bindings.setdefault((scope(node), node.arg), []).append(node)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store) and name.id != DECLARATION:
                        bindings.setdefault((scope(node), name.id), []).append(node.value)
        if isinstance(node, (ast.For, ast.comprehension)):
            for name in ast.walk(node.target):
                if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                    bindings.setdefault((scope(node), name.id), []).append(node.iter)

    def values_for(node):
        return bindings.get((scope(node), node.id), bindings.get((tree, node.id), []))

    def callable_name(node, seen=frozenset()):
        if isinstance(node, ast.Attribute):
            return callable_name(node.value, seen) + "." + node.attr
        if not isinstance(node, ast.Name) or node.id in seen:
            return ""
        values = values_for(node)
        if values:
            resolved = {callable_name(value, seen | {node.id}) for value in values}
            return resolved.pop() if len(resolved) == 1 else ""
        return imports.get((scope(node), node.id), imports.get((tree, node.id), node.id))

    has_declaration_source = declaration is not None or any(
        isinstance(node, ast.arg) and node.arg == "llm_decompile_specs" for node in ast.walk(tree)
    )

    def origin(node, seen=frozenset(), *, any_binding=False):
        if any_binding and not has_declaration_source:
            return False
        if isinstance(node, ast.Name):
            if node.id == DECLARATION:
                return declaration is not None
            key = (scope(node), node.id)
            if key in seen:
                return False
            values = values_for(node)
            if node.id == "llm_decompile_specs" and len(values) == 1 and isinstance(values[0], ast.arg):
                parent = scope(node)
                return (
                    isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and parent.name != "preprocess_skill"
                    and any(
                        a.arg == node.id and default is None
                        for a, default in zip(parent.args.kwonlyargs, parent.args.kw_defaults)
                    )
                )
            if values:
                results = [origin(value, seen | {key}, any_binding=any_binding) for value in values]
                return any(results) if any_binding else all(results)
            return False
        if isinstance(node, ast.Subscript):
            return origin(node.value, seen, any_binding=any_binding)
        if isinstance(node, ast.IfExp):
            results = [origin(value, seen, any_binding=any_binding) for value in (node.body, node.orelse)]
            return any(results) if any_binding else all(results)
        if isinstance(node, ast.Constant) and node.value is None:
            return not any_binding
        if isinstance(node, ast.Call) and callable_name(node.func) == "llm_spec.select_llm_specs":
            return (
                len(node.args) == 1
                and all(k.arg in {"branch", "symbols", "expected_values", "instruction_rules"} for k in node.keywords)
                and origin(node.args[0], seen, any_binding=any_binding)
            )
        container_expression = (
            isinstance(
                node,
                (
                    ast.List,
                    ast.Tuple,
                    ast.Set,
                    ast.Dict,
                    ast.Starred,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                    ast.BinOp,
                    ast.BoolOp,
                ),
            )
            or isinstance(node, ast.Call)
            and callable_name(node.func) in {"dict", "list", "tuple", "set", "frozenset"}
        )
        if any_binding and container_expression:
            # A shallow container/copy is not an approved source of runtime specs,
            # but it can still share mutable objects with the declaration.
            return any(
                isinstance(child, ast.Name) and origin(child, seen, any_binding=True)
                for child in ast.walk(node)
                if child is not node
            )
        return False

    def literal_kwargs(node, seen=frozenset()):
        if isinstance(node, ast.Dict):
            return all(isinstance(key, ast.Constant) and isinstance(key.value, str) for key in node.keys)
        if isinstance(node, ast.Name):
            key = (scope(node), node.id)
            values = values_for(node)
            return key not in seen and bool(values) and all(literal_kwargs(value, seen | {key}) for value in values)
        return False

    kwargs_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = callable_name(node.func)
            if name in {"ida_analyze_util.preprocess_common_skill", "preprocess_common_skill"}:
                # Require keywords beyond session/outputs, including star imports.
                if len(node.args) > 2 or any(isinstance(a, ast.Starred) for a in node.args):
                    _fail(
                        path, node, "preprocess_common_skill arguments after session/outputs must be explicit keywords"
                    )
            # All execution/forwarding calls use explicit keyword dictionaries.
            # Plain dict construction is allowed for unrelated artifact payloads;
            # it never qualifies as an approved origin of LLM specs.
            if name == "dict":
                continue
            for keyword in node.keywords:
                if keyword.arg is None:
                    if not literal_kwargs(keyword.value):
                        _fail(
                            path,
                            keyword,
                            "Execution/forwarding **kwargs must be a literal dictionary or its local alias",
                        )
                    kwargs_names.update(n.id for n in ast.walk(keyword.value) if isinstance(n, ast.Name))
    # Include aliases of kwargs so mutation through either name is rejected.
    changed = True
    while changed:
        before = len(kwargs_names)
        for (_, name), values in bindings.items():
            if name in kwargs_names or any(isinstance(v, ast.Name) and v.id in kwargs_names for v in values):
                kwargs_names.add(name)
                kwargs_names.update(v.id for v in values if isinstance(v, ast.Name))
        changed = len(kwargs_names) != before

    def protected(node):
        while isinstance(node, (ast.Subscript, ast.Attribute)):
            node = node.value
        return origin(node, any_binding=True) or isinstance(node, ast.Name) and node.id in kwargs_names

    for node in ast.walk(tree):
        if node in declaration_nodes:
            continue
        if (
            isinstance(node, (ast.Subscript, ast.Attribute))
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and protected(node)
        ):
            _fail(
                path,
                node,
                "LLM_DECOMPILE selections/kwargs must not be mutated; use select_llm_specs for runtime fields",
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and protected(node.func.value):
            _fail(path, node, "LLM_DECOMPILE mutation/method calls are unsupported")
        if isinstance(node, ast.Call):
            name = callable_name(node.func)
            readers = {
                "llm_spec.select_llm_specs",
                "llm_spec.normalize_llm_decompile_specs",
                "ida_analyze_util._normalize_llm_decompile_specs",
                "ida_analyze_util._prepare_llm_context",
            }
            if name not in readers and any(
                isinstance(child, ast.Name) and origin(child, any_binding=True)
                for arg in node.args
                for child in ast.walk(arg)
            ):
                _fail(path, node, "LLM_DECOMPILE may only be passed to audited readers or via llm_decompile_specs=")
            for keyword in node.keywords:
                if (
                    keyword.arg not in {None, "llm_decompile_specs"}
                    and name not in readers
                    and any(
                        isinstance(child, ast.Name) and origin(child, any_binding=True)
                        for child in ast.walk(keyword.value)
                    )
                ):
                    _fail(path, keyword, "Forward declarations using llm_decompile_specs=")
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in {"symbol_name", "reference_yaml_paths", "prompt_path", "dependency_policy"}
        ):
            _fail(path, node, "LLM dependency fields cannot be assigned outside LLM_DECOMPILE")
        sinks = []
        if isinstance(node, ast.keyword) and node.arg == "llm_decompile_specs":
            sinks.append(node.value)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "llm_decompile_specs"
        ):
            _fail(
                path,
                node,
                "Declare llm_decompile_specs in a literal kwargs dictionary; later assignment is unsupported",
            )
        if isinstance(node, ast.Dict):
            sinks.extend(
                value
                for key, value in zip(node.keys, node.values)
                if isinstance(key, ast.Constant) and key.value == "llm_decompile_specs"
            )
        if isinstance(node, ast.Call) and callable_name(node.func) in {
            "ida_analyze_util._normalize_llm_decompile_specs",
            "llm_spec.normalize_llm_decompile_specs",
        }:
            sinks.extend(node.args[:1])
        for sink in sinks:
            if not origin(sink):
                _fail(
                    path,
                    sink,
                    "llm_decompile_specs must come from static LLM_DECOMPILE (or a keyword-only forwarding helper parameter)",
                )
        if isinstance(node, ast.Dict) and any(
            isinstance(key, ast.Constant) and key.value in {"reference_yaml_paths", "dependency_policy", "prompt_path"}
            for key in node.keys
        ):
            _fail(path, node, "LLM dependency fields must be defined inside LLM_DECOMPILE")
        if isinstance(node, ast.Call) and any(
            k.arg in {"reference_yaml_paths", "dependency_policy", "prompt_path"} for k in node.keywords
        ):
            _fail(path, node, "LLM dependency fields must be defined inside LLM_DECOMPILE")


def validate_declarations(tree):
    """Audit every preprocessor source, including currently unregistered entries."""
    for path, source in sorted(tree.items()):
        if path.startswith("ida_preprocessor_scripts/") and path.endswith(".py"):
            parse_declaration(source.decode("utf-8") if isinstance(source, bytes) else source, path)
