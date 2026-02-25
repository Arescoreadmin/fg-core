from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class AuthClass:
    required_scope_prefixes: tuple[str, ...] = ()
    require_any_scope: bool = False
    tenant_binding_required: bool = True
    allow_unscoped_keys: bool = False


@dataclass(frozen=True)
class RouteException:
    method: str
    path: str
    class_name: str
    justification: str
    permanent: bool = True
    expires_at: str = ""


@dataclass(frozen=True)
class PlaneDef:
    plane_id: str
    route_prefixes: tuple[str, ...]
    allowed_dependency_categories: tuple[str, ...] = ()
    required_make_targets: tuple[str, ...] = ()
    required_ci_gates: tuple[str, ...] = ()
    maturity_tag: str = "production-grade"
    required_route_invariants: tuple[str, ...] = ()
    auth_class: AuthClass = field(default_factory=AuthClass)
    global_routes: tuple[RouteException, ...] = ()
    public_routes: tuple[RouteException, ...] = ()
    bootstrap_routes: tuple[RouteException, ...] = ()
    auth_exempt_routes: tuple[RouteException, ...] = ()
    docs_routes: tuple[RouteException, ...] = ()

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["route_prefixes"] = list(self.route_prefixes)
        data["allowed_dependency_categories"] = list(self.allowed_dependency_categories)
        data["required_make_targets"] = list(self.required_make_targets)
        data["required_ci_gates"] = list(self.required_ci_gates)
        data["required_route_invariants"] = list(self.required_route_invariants)
        return data
