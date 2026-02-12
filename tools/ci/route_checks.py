from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from api.public_paths import LINTER_PUBLIC_PATH_PREFIXES

HTTP_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
PUBLIC_PATH_PREFIXES = LINTER_PUBLIC_PATH_PREFIXES


@dataclass(frozen=True)
class RouteRecord:
    file_path: Path
    function_name: str
    method: str
    full_path: str
    route_has_scope_dependency: bool
    route_has_db_dependency: bool


class RouteExtractor(ast.NodeVisitor):
    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.router_prefixes: dict[str, str] = {}
        self.router_scope_dependency: dict[str, bool] = {}
        self.records: list[RouteRecord] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        if (
            isinstance(node.value, ast.Call)
            and _get_name(node.value.func) == "APIRouter"
        ):
            prefix = _literal_kwarg(node.value, "prefix") or ""
            has_scope_dep = _dependencies_include_scope(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.router_prefixes[target.id] = prefix
                    self.router_scope_dependency[target.id] = has_scope_dep
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_route_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_route_function(node)
        self.generic_visit(node)

    def _visit_route_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            if not isinstance(deco.func, ast.Attribute):
                continue
            router_name = _get_name(deco.func.value)
            method = deco.func.attr
            if router_name is None or method not in HTTP_ROUTE_METHODS:
                continue

            route_path = ""
            if deco.args:
                route_path = _literal(deco.args[0]) or ""
            route_path = route_path or (_literal_kwarg(deco, "path") or "")
            full_path = _normalize_path(
                self.router_prefixes.get(router_name, ""), route_path
            )

            route_scope = _dependencies_include_scope(
                deco
            ) or _function_has_scope_dependency(node)
            if self.router_scope_dependency.get(router_name, False):
                route_scope = True
            route_db = _dependencies_include_get_db(
                deco
            ) or _function_has_get_db_dependency(node)

            self.records.append(
                RouteRecord(
                    file_path=self.file_path,
                    function_name=node.name,
                    method=method.upper(),
                    full_path=full_path,
                    route_has_scope_dependency=route_scope,
                    route_has_db_dependency=route_db,
                )
            )


def iter_route_records(root: Path) -> list[RouteRecord]:
    records: list[RouteRecord] = []
    for py_file in sorted(root.glob("**/*.py")):
        if "tests" in py_file.parts:
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        extractor = RouteExtractor(py_file)
        extractor.visit(tree)
        records.extend(extractor.records)
    return records


def is_public_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES)


def _normalize_path(prefix: str, path: str) -> str:
    raw = "/".join(part.strip("/") for part in (prefix, path) if part)
    return "/" + raw if raw else "/"


def _literal_kwarg(call: ast.Call, name: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == name:
            return _literal(kw.value)
    return None


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _get_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _get_name(node.value)
        if left:
            return f"{left}.{node.attr}"
    return None


def _dependencies_include_scope(call: ast.Call) -> bool:
    dep_node = _keyword_value(call, "dependencies")
    if not isinstance(dep_node, (ast.List, ast.Tuple)):
        return False
    return any(_is_scope_dependency(dep) for dep in dep_node.elts)


def _dependencies_include_get_db(call: ast.Call) -> bool:
    dep_node = _keyword_value(call, "dependencies")
    if not isinstance(dep_node, (ast.List, ast.Tuple)):
        return False
    return any(_is_get_db_dependency(dep) for dep in dep_node.elts)


def _function_has_scope_dependency(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    args = [*node.args.args, *node.args.kwonlyargs]
    if node.args.vararg:
        args.append(node.args.vararg)
    if node.args.kwarg:
        args.append(node.args.kwarg)
    for arg in args:
        default = _default_for_arg(node, arg.arg)
        if default is not None and _is_scope_dependency(default):
            return True
    return False


def _function_has_get_db_dependency(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    args = [*node.args.args, *node.args.kwonlyargs]
    if node.args.vararg:
        args.append(node.args.vararg)
    if node.args.kwarg:
        args.append(node.args.kwarg)
    for arg in args:
        default = _default_for_arg(node, arg.arg)
        if default is not None and _is_get_db_dependency(default):
            return True
    return False


def _default_for_arg(
    node: ast.FunctionDef | ast.AsyncFunctionDef, arg_name: str
) -> ast.AST | None:
    positional_args = node.args.args
    positional_defaults = node.args.defaults
    pos_default_start = len(positional_args) - len(positional_defaults)
    for idx, arg in enumerate(positional_args):
        if arg.arg != arg_name:
            continue
        if idx >= pos_default_start:
            return positional_defaults[idx - pos_default_start]
        return None

    for kw_arg, kw_default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        if kw_arg.arg == arg_name:
            return kw_default

    return None


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_scope_dependency(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if _get_name(node.func) != "Depends" or not node.args:
        return False
    dep_name = _get_name(node.args[0])
    if dep_name in {"require_scopes", "authz_scope"}:
        return True
    if isinstance(node.args[0], ast.Call):
        nested_name = _get_name(node.args[0].func)
        return nested_name in {"require_scopes", "authz_scope"}
    return False


def _is_get_db_dependency(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if _get_name(node.func) != "Depends" or not node.args:
        return False
    dep_name = _get_name(node.args[0])
    return dep_name in {"get_db", "api.db.get_db", "api.deps.get_db"}
