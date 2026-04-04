from __future__ import annotations

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol, cast
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from api.config.env import is_production_env, is_strict_env_required, resolve_env
from api.config.prod_invariants import assert_prod_invariants
from api.config.spine_modules import load_spine_modules
from api.config.startup_validation import (
    compliance_module_enabled,
    validate_startup_config,
)
from api.db import init_db
from api.attestation import router as attestation_router
from api.audit import router as audit_router
from api.auth_federation import router as auth_federation_router
from api.billing import router as billing_router
from api.compliance import router as compliance_router
from api.compliance_cp_extension import router as compliance_cp_extension_router
from api.config_control import router as config_control_router
from api.connectors_control_plane import router as connectors_control_plane_router
from api.control_plane import router as control_plane_router
from api.control_plane_v2 import router as control_plane_v2_router
from api.control_tower_snapshot import router as control_tower_snapshot_router
from api.decisions import router as decisions_router
from api.defend import router as defend_router
from api.dev_events import router as dev_events_router
from api.enterprise_controls import router as enterprise_controls_router
from api.evidence_anchors import router as evidence_anchors_router
from api.evidence_index import router as evidence_index_router
from api.exception_breakglass import router as exception_breakglass_router
from api.feed import router as feed_router
from api.forensics import router as forensics_router
from api.ingest import router as ingest_router
from api.keys import router as keys_router
from api.planes import router as planes_router
from api.stats import router as stats_router
from api.testing_control_tower import router as testing_control_tower_router
from api.ui import router as ui_router
from api.ui_ai_console import admin_router as ui_ai_admin_router
from api.ui_ai_console import router as ui_ai_router
from api.ui_audit_dashboard import router as ui_audit_dashboard_router
from api.ui_compliance_dashboard import router as ui_compliance_dashboard_router
from api.ui_dashboards import router as ui_dashboards_router
from api.ui_testing_control_tower import router as ui_testing_control_tower_router
from api.ai_plane_extension import router as ai_plane_extension_router
from api.agent_enrollment import router as agent_enrollment_router
from api.agent_phase2 import admin_router as agent_phase2_admin_router
from api.agent_phase2 import router as agent_phase2_router
from api.agent_tokens import router as agent_tokens_router
from api.middleware.auth_gate import AuthGateConfig, AuthGateMiddleware
from api.middleware.dos_guard import DoSGuardConfig, DoSGuardMiddleware
from api.middleware.exception_shield import FGExceptionShieldMiddleware
from api.middleware.request_validation import (
    RequestValidationConfig,
    RequestValidationMiddleware,
)
from api.middleware.resilience_guard import ResilienceGuardMiddleware
from api.middleware.security_headers import (
    CORSConfig,
    SecurityHeadersConfig,
    SecurityHeadersMiddleware,
)
from services.ai_plane_extension import ai_external_provider_enabled, ai_plane_enabled
from services.self_heal import SelfHealWatchdog

log = logging.getLogger("frostgate")

APP_VERSION = "0.8.0"
API_VERSION = "v1"

ERR_INVALID = "Invalid or missing API key"
UI_COOKIE_NAME = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")


class ContractSettingsLike(Protocol):
    @property
    def title(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def servers(self) -> tuple[dict[str, str], ...]: ...


@dataclass(frozen=True)
class ContractAppSettings:
    title: str = "frostgate-core"
    version: str = APP_VERSION
    servers: tuple[dict[str, str], ...] = ()
    service: str = "frostgate-core"
    env: str = "contract"
    app_instance_id: str = "contract-build"


get_shutdown_manager = None

_TRUE = {"1", "true", "yes", "y", "on"}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in _TRUE


def _admin_enabled_flag() -> bool:
    return _env_bool("FG_ADMIN_ENABLED", default=False)


def _should_mount_admin_routes() -> bool:
    if is_production_env():
        return _admin_enabled_flag()
    return True


def _testing_control_tower_enabled() -> bool:
    return _env_bool("FG_TESTING_CONTROL_TOWER_ENABLED", default=False)


def _resolve_auth_enabled_from_env() -> bool:
    if os.getenv("FG_AUTH_ENABLED") is not None:
        return _env_bool("FG_AUTH_ENABLED", default=False)
    return bool((os.getenv("FG_API_KEY") or "").strip())


def _sanitize_db_url(db_url: str) -> str:
    try:
        parsed = urlparse(db_url)
        scheme = (parsed.scheme or "db").split("+", 1)[0]
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        dbname = (parsed.path or "").lstrip("/")
        if host or dbname:
            return f"{scheme}://{host}{port}/{dbname}"
        return f"{scheme}://(unresolved)"
    except Exception:
        return "db_url:unparseable"


def _global_expected_api_key() -> str:
    return (os.getenv("FG_API_KEY") or "").strip()


def _dev_enabled() -> bool:
    return (os.getenv("FG_DEV_EVENTS_ENABLED") or "0").strip() == "1"


def _is_production_runtime() -> bool:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    return env in {"prod", "production", "staging"}


def _sqlite_path_from_env() -> str:
    sqlite_path = (
        os.getenv("FG_SQLITE_PATH") or os.getenv("SQLITE_PATH") or ""
    ).strip()
    if sqlite_path:
        return sqlite_path
    return str(Path("/tmp") / "fg-core.db")


def _optional_router(import_path: str, attr: str = "router") -> Any | None:
    try:
        module = __import__(import_path, fromlist=[attr])
        return getattr(module, attr)
    except Exception:
        return None


def _add_middleware(app: FastAPI, middleware_cls: Any, **kwargs: Any) -> None:
    app.add_middleware(cast(Any, middleware_cls), **kwargs)


governance_router = _optional_router("api.governance", "router")
mission_router = _optional_router("api.mission_envelope", "router")
ring_router = _optional_router("api.ring_router", "router")
roe_router = _optional_router("api.roe_engine", "router")


def build_app(auth_enabled: Optional[bool] = None) -> FastAPI:
    resolved_auth_enabled = (
        _resolve_auth_enabled_from_env() if auth_enabled is None else bool(auth_enabled)
    )
    spine_modules = load_spine_modules()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        effective_env = (os.getenv("FG_ENV") or "").strip()
        source = "FG_ENV"

        if not effective_env:
            try:
                effective_env = str(resolve_env())
                source = "resolve_env()"
            except Exception:
                effective_env = "unknown"
                source = "unknown"

        log.info("effective_env=%s source=%s", effective_env, source)
        app.state.effective_env = effective_env
        app.state.effective_env_source = source

        if ai_external_provider_enabled():
            raise RuntimeError("AI_EXTERNAL_PROVIDER_NOT_ALLOWED")

        assert_prod_invariants()
        is_production = False
        try:
            is_production = is_production_env()
            report = validate_startup_config(
                fail_on_error=is_production,
                log_results=True,
            )
            app.state.startup_validation = report

            if is_production and not bool(
                getattr(app.state, "dos_guard_enabled", False)
            ):
                raise RuntimeError("DoS guard middleware must be enabled in production")
        except Exception as exc:
            log.warning("Startup validation failed: %s", exc)
            app.state.startup_validation = None
            if is_production or is_strict_env_required():
                raise

        try:
            if not (os.getenv("FG_DB_URL") or "").strip():
                sqlite_path = _sqlite_path_from_env()
                Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)

            init_db()
            app.state.db_init_ok = True
            app.state.db_init_error = None
        except Exception as exc:
            app.state.db_init_ok = False
            app.state.db_init_error = f"{type(exc).__name__}: {exc}"
            log.exception("DB init failed")
            if is_production or is_strict_env_required():
                raise

        self_heal_watchdog = SelfHealWatchdog()
        self_heal_watchdog.start()
        app.state.self_heal_watchdog = self_heal_watchdog

        shutdown_factory = getattr(spine_modules, "get_shutdown_manager", None)
        if callable(shutdown_factory):
            try:
                shutdown_manager = shutdown_factory()
                await shutdown_manager.setup()
                app.state.shutdown_manager = shutdown_manager
                log.info("Graceful shutdown handler initialized")
            except Exception as exc:
                log.warning("Graceful shutdown setup failed: %s", exc)
                app.state.shutdown_manager = None
        else:
            app.state.shutdown_manager = None

        yield

        if hasattr(app.state, "self_heal_watchdog"):
            try:
                app.state.self_heal_watchdog.stop()
            except Exception:
                pass

        shutdown_manager = getattr(app.state, "shutdown_manager", None)
        if shutdown_manager is not None:
            try:
                await shutdown_manager.initiate_shutdown("Application shutdown")
            except Exception as exc:
                log.warning("Graceful shutdown error: %s", exc)

    app = FastAPI(title="frostgate-core", version=APP_VERSION, lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        if request.url.path == "/ingest":
            errs = exc.errors()
            if any(
                err.get("loc") == ("body", "event_id") and err.get("type") == "missing"
                for err in errs
            ):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error_code": "INGEST_EVENT_ID_REQUIRED",
                        "detail": {
                            "error": {
                                "code": "INGEST_EVENT_ID_REQUIRED",
                                "message": "event_id is required",
                            }
                        },
                    },
                )
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    if not hasattr(app.state, "_ui_single_use_used"):
        app.state._ui_single_use_used = set()
    if not hasattr(app.state, "_ui_key_scopes_cache"):
        app.state._ui_key_scopes_cache = {}

    single_use_exact = {"/ui/posture", "/ui/decisions", "/ui/controls"}
    single_use_prefixes = ("/ui/decision/",)
    single_use_ui_scoped_exact = {"/ui/forensics/chain/verify"}

    def _b64url_decode(value: str) -> bytes:
        import base64

        normalized = value.strip().replace("-", "+").replace("_", "/")
        pad = "=" * ((4 - (len(normalized) % 4)) % 4)
        return base64.b64decode(normalized + pad)

    def _scopes_from_key(api_key: str) -> frozenset[str]:
        cache = app.state._ui_key_scopes_cache
        if api_key in cache:
            return cache[api_key]

        scopes: frozenset[str] = frozenset()
        try:
            parts = api_key.split(".", 2)
            if len(parts) >= 2:
                payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
                raw_scopes = payload.get("scopes") or []
                if isinstance(raw_scopes, list):
                    scopes = frozenset(str(item) for item in raw_scopes)
        except Exception:
            scopes = frozenset()

        cache[api_key] = scopes
        return scopes

    @app.middleware("http")
    async def _ui_single_use_key_guard(request: Request, call_next):
        if request.method == "GET":
            path = request.url.path

            is_single_use = (path in single_use_exact) or path.startswith(
                single_use_prefixes
            )

            if (not is_single_use) and (path in single_use_ui_scoped_exact):
                key = request.headers.get("x-api-key") or request.headers.get(
                    "X-API-Key"
                )
                if key and "ui:read" in _scopes_from_key(key):
                    is_single_use = True

            if is_single_use:
                key = request.headers.get("x-api-key") or request.headers.get(
                    "X-API-Key"
                )
                if key:
                    token = (key, request.method, path)
                    used = app.state._ui_single_use_used
                    if token in used:
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "single-use ui key already used"},
                        )
                    used.add(token)

        return await call_next(request)

    _add_middleware(app, FGExceptionShieldMiddleware)

    connection_tracking_middleware = getattr(
        spine_modules, "connection_tracking_middleware", None
    )
    if connection_tracking_middleware is not None:
        _add_middleware(app, connection_tracking_middleware)

    _add_middleware(
        app,
        SecurityHeadersMiddleware,
        config=SecurityHeadersConfig.from_env(),
    )

    cors_config = CORSConfig.from_env()
    _add_middleware(
        app,
        CORSMiddleware,
        allow_origins=cors_config.allow_origins,
        allow_credentials=cors_config.allow_credentials,
        allow_methods=cors_config.allow_methods,
        allow_headers=cors_config.allow_headers,
        expose_headers=cors_config.expose_headers,
        max_age=cors_config.max_age,
    )

    dos_guard_config = DoSGuardConfig.from_env()
    _add_middleware(app, DoSGuardMiddleware, config=dos_guard_config)
    _add_middleware(
        app,
        RequestValidationMiddleware,
        config=RequestValidationConfig.from_env(),
    )
    _add_middleware(app, ResilienceGuardMiddleware)

    app.state.auth_enabled = bool(resolved_auth_enabled)
    app.state.service = os.getenv("FG_SERVICE", "frostgate-core")
    app.state.env = resolve_env()
    app.state.app_instance_id = str(uuid.uuid4())
    app.state.app_version = APP_VERSION
    app.state.api_version = API_VERSION
    app.state.db_init_ok = False
    app.state.db_init_error = None
    app.state.startup_validation = None
    app.state.dos_guard_enabled = bool(dos_guard_config.enabled)

    def _fail(detail: str = ERR_INVALID) -> None:
        raise HTTPException(status_code=401, detail=detail)

    def _hdr(req: Request, name: str) -> Optional[str]:
        value = req.headers.get(name)
        value = str(value).strip() if value is not None else ""
        return value or None

    def check_tenant_if_present(req: Request) -> None:
        tenant_id = _hdr(req, "X-Tenant-Id")
        if not tenant_id:
            return

        api_key = _hdr(req, "X-API-Key")
        if not api_key and not _is_production_runtime():
            cookie_value = req.cookies.get(UI_COOKIE_NAME)
            api_key = (
                str(cookie_value).strip()
                if cookie_value and str(cookie_value).strip()
                else None
            )
        if not api_key:
            _fail()

        try:
            import api.auth as auth_mod
        except Exception:
            _fail()

        get_tenant = getattr(auth_mod, "get_tenant", None)
        if not callable(get_tenant):
            _fail()

        tenant = get_tenant(str(tenant_id))
        if tenant is None:
            _fail()

        status = getattr(tenant, "status", None)
        if status and str(status).lower() != "active":
            _fail("Tenant revoked")

        expected = getattr(tenant, "api_key", None)
        if expected is None or str(expected) != str(api_key):
            _fail()

    def require_status_auth(req: Request) -> None:
        check_tenant_if_present(req)

        if not bool(app.state.auth_enabled):
            return

        api_key = _hdr(req, "X-API-Key")
        if not api_key and not _is_production_runtime():
            cookie_value = req.cookies.get(UI_COOKIE_NAME)
            api_key = (
                str(cookie_value).strip()
                if cookie_value and str(cookie_value).strip()
                else None
            )
        if not api_key:
            _fail()

        if api_key != _global_expected_api_key():
            _fail()

    try:
        import api.auth as auth_mod

        if not hasattr(auth_mod, "require_status_auth"):
            setattr(auth_mod, "require_status_auth", require_status_auth)
    except Exception:
        pass

    _add_middleware(
        app,
        AuthGateMiddleware,
        require_status_auth=require_status_auth,
        config=AuthGateConfig(),
    )

    app.include_router(defend_router)
    app.include_router(defend_router, prefix="/v1")
    app.include_router(ingest_router)
    app.include_router(feed_router)
    app.include_router(decisions_router)
    app.include_router(stats_router)
    app.include_router(attestation_router)
    app.include_router(config_control_router)
    app.include_router(billing_router)
    app.include_router(audit_router)
    app.include_router(compliance_router)
    app.include_router(compliance_cp_extension_router)
    app.include_router(enterprise_controls_router)
    app.include_router(exception_breakglass_router)
    app.include_router(evidence_anchors_router)
    app.include_router(auth_federation_router)
    if ai_plane_enabled():
        app.include_router(ai_plane_extension_router)
    app.include_router(planes_router)
    app.include_router(evidence_index_router)

    if not _is_production_runtime():
        app.include_router(ui_router)
        app.include_router(ui_dashboards_router)
        app.include_router(ui_audit_dashboard_router)
        app.include_router(ui_compliance_dashboard_router)
        app.include_router(ui_ai_router)
        app.include_router(ui_ai_admin_router)
        if _testing_control_tower_enabled():
            app.include_router(ui_testing_control_tower_router)

    app.include_router(keys_router)
    app.include_router(forensics_router)
    app.include_router(agent_enrollment_router)
    app.include_router(agent_tokens_router)
    app.include_router(agent_phase2_router)
    app.include_router(connectors_control_plane_router)
    app.include_router(control_plane_router)
    app.include_router(control_plane_v2_router)
    app.include_router(control_tower_snapshot_router)

    if _testing_control_tower_enabled():
        app.include_router(testing_control_tower_router)
    if _should_mount_admin_routes():
        app.include_router(agent_phase2_admin_router)

    if compliance_module_enabled("mission_envelope") and mission_router is not None:
        app.include_router(mission_router)
    if compliance_module_enabled("ring_router") and ring_router is not None:
        app.include_router(ring_router)
    if compliance_module_enabled("roe_engine") and roe_router is not None:
        app.include_router(roe_router)
    if compliance_module_enabled("governance") and governance_router is not None:
        app.include_router(governance_router)

    if _dev_enabled():
        app.include_router(dev_events_router)

    admin_router = getattr(spine_modules, "admin_router", None)
    if admin_router is not None and _should_mount_admin_routes():
        app.include_router(admin_router)

    @app.get("/health")
    async def health(request: Request) -> dict[str, Any]:
        return {
            "status": "ok",
            "service": request.app.state.service,
            "version": request.app.state.app_version,
            "api_version": request.app.state.api_version,
            "env": request.app.state.env,
            "auth_enabled": bool(request.app.state.auth_enabled),
            "app_instance_id": request.app.state.app_instance_id,
        }

    @app.get(
        "/health/live",
        description="Kubernetes liveness probe - is the service running?",
    )
    async def health_live() -> dict[str, str]:
        return {"status": "live"}

    @app.get(
        "/health/ready",
        description="Kubernetes readiness probe - can the service handle traffic?",
    )
    async def health_ready() -> dict[str, Any]:
        from api.health import HealthStatus, get_health_checker

        deps_status: dict[str, Any] = {"db": "unknown"}
        failures: list[str] = []

        startup_validation = getattr(app.state, "startup_validation", None)
        if startup_validation is None:
            raise HTTPException(
                status_code=503, detail="startup_validation_unavailable"
            )
        if getattr(startup_validation, "has_errors", False):
            raise HTTPException(status_code=503, detail="startup_validation_failed")

        if not bool(app.state.db_init_ok):
            raise HTTPException(
                status_code=503,
                detail=f"db_init_failed: {app.state.db_init_error or 'unknown'}",
            )

        if (os.getenv("FG_DB_URL") or "").strip():
            deps_status["db"] = "postgres"
        else:
            sqlite_path = Path(_sqlite_path_from_env())
            if not sqlite_path.exists():
                raise HTTPException(
                    status_code=503, detail=f"DB missing: {sqlite_path}"
                )
            deps_status["db"] = "sqlite"

        checker = None
        try:
            checker = get_health_checker()
        except Exception:
            deps_status["checker"] = "error"
            checker = None

        rl_enabled = (os.getenv("FG_RL_ENABLED", "true") or "true").strip().lower()
        rl_backend = (os.getenv("FG_RL_BACKEND", "memory") or "memory").strip().lower()

        if rl_enabled in _TRUE and rl_backend == "redis":
            if checker is None:
                deps_status["redis"] = "error"
                failures.append("redis: health checker unavailable")
            else:
                try:
                    redis_check = checker.check_redis()
                    if redis_check is not None:
                        deps_status["redis"] = redis_check.status.value
                        if redis_check.status == HealthStatus.UNHEALTHY:
                            failures.append(
                                f"redis: {redis_check.message or 'unhealthy'}"
                            )
                    else:
                        deps_status["redis"] = "unknown"
                except Exception as exc:
                    deps_status["redis"] = "error"
                    failures.append(f"redis: {type(exc).__name__}: {exc}")

        nats_enabled = (
            (os.getenv("FG_NATS_ENABLED", "false") or "false").strip().lower()
        )
        if nats_enabled in _TRUE:
            if checker is None:
                deps_status["nats"] = "error"
                failures.append("nats: health checker unavailable")
            else:
                check_nats = getattr(checker, "check_nats", None)
                if not callable(check_nats):
                    deps_status["nats"] = "not_supported"
                    log.warning(
                        "NATS enabled but no check_nats() available; skipping NATS readiness enforcement"
                    )
                else:
                    try:
                        nats_check = check_nats()
                        if nats_check is not None:
                            deps_status["nats"] = nats_check.status.value
                            if nats_check.status == HealthStatus.UNHEALTHY:
                                failures.append(
                                    f"nats: {nats_check.message or 'unhealthy'}"
                                )
                        else:
                            deps_status["nats"] = "unknown"
                    except Exception as exc:
                        deps_status["nats"] = "error"
                        failures.append(f"nats: {type(exc).__name__}: {exc}")

        if failures:
            raise HTTPException(
                status_code=503,
                detail=f"dependencies_unhealthy: {'; '.join(failures)}",
            )

        return {"status": "ready", "dependencies": deps_status}

    @app.get("/health/detailed")
    async def health_detailed(_: None = Depends(require_status_auth)) -> dict[str, Any]:
        try:
            from api.health import check_health_detailed

            return check_health_detailed()
        except Exception as exc:
            log.exception("Detailed health check failed")
            return {"status": "unhealthy", "error": str(exc)}

    @app.get("/status")
    async def status(_: None = Depends(require_status_auth)) -> dict[str, str]:
        return {"status": "ok", "service": app.state.service, "env": app.state.env}

    @app.get("/v1/status")
    async def v1_status(_: None = Depends(require_status_auth)) -> dict[str, str]:
        return {"status": "ok", "service": app.state.service, "env": app.state.env}

    @app.get("/stats/debug")
    async def stats_debug(_: None = Depends(require_status_auth)) -> dict[str, Any]:
        db_url = (os.getenv("FG_DB_URL") or "").strip()
        result: dict[str, Any] = {
            "service": app.state.service,
            "env": app.state.env,
            "app_instance_id": app.state.app_instance_id,
            "auth_enabled": bool(app.state.auth_enabled),
            "db_mode": "url" if db_url else "sqlite",
            "db_init_ok": bool(app.state.db_init_ok),
            "db_init_error": app.state.db_init_error,
            "fg_state_dir": os.getenv("FG_STATE_DIR"),
            "fg_sqlite_path_env": os.getenv("FG_SQLITE_PATH"),
        }

        if db_url:
            result["stats_source_db"] = _sanitize_db_url(db_url)
            result["stats_source_db_size_bytes"] = None
            return result

        try:
            sqlite_path = Path(_sqlite_path_from_env())
            exists = sqlite_path.exists()
            size = sqlite_path.stat().st_size if exists else 0
            result["sqlite_path_resolved"] = str(sqlite_path)
            result["sqlite_exists"] = exists
            result["sqlite_size_bytes"] = size
            result["stats_source_db"] = f"sqlite:{sqlite_path}"
            result["stats_source_db_size_bytes"] = size
        except Exception as exc:
            result["sqlite_path_resolved_error"] = f"{type(exc).__name__}: {exc}"
            result["stats_source_db"] = "sqlite:unresolved"
            result["stats_source_db_size_bytes"] = 0

        return result

    @app.get("/_debug/routes")
    async def debug_routes(request: Request) -> dict[str, Any]:
        try:
            require_status_auth(request)

            routes: list[dict[str, Any]] = []
            for route in request.app.router.routes:
                path = getattr(route, "path", None)
                if not path:
                    continue
                endpoint = getattr(route, "endpoint", None)
                module_name = (
                    getattr(endpoint, "__module__", None) if endpoint else None
                )
                func_name = getattr(endpoint, "__name__", None) if endpoint else None
                methods = sorted(list(getattr(route, "methods", []) or []))

                routes.append(
                    {
                        "path": path,
                        "methods": methods,
                        "endpoint": f"{module_name}.{func_name}"
                        if module_name and func_name
                        else None,
                        "name": getattr(route, "name", None),
                    }
                )

            routes.sort(key=lambda item: (str(item["path"]), ",".join(item["methods"])))
            return {"ok": True, "error": None, "routes": routes}
        except HTTPException as exc:
            return {
                "ok": False,
                "error": f"{exc.status_code}: {exc.detail}",
                "routes": [],
            }
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "routes": []}

    return app


def build_runtime_app(auth_enabled: Optional[bool] = None) -> FastAPI:
    return build_app(auth_enabled=auth_enabled)


def build_contract_app(settings: ContractSettingsLike | None = None) -> FastAPI:
    cfg = settings or ContractAppSettings()
    app = FastAPI(
        title=cfg.title,
        version=cfg.version,
        servers=list(cfg.servers),
        root_path="",
    )
    app.state.auth_enabled = True
    app.state.service = getattr(cfg, "service", "frostgate-core")
    app.state.env = getattr(cfg, "env", "contract")
    app.state.app_instance_id = getattr(cfg, "app_instance_id", "contract-build")
    app.state.app_version = cfg.version
    app.state.api_version = API_VERSION

    app.include_router(ingest_router)
    app.include_router(defend_router)
    app.include_router(feed_router)
    app.include_router(decisions_router)
    app.include_router(stats_router)
    app.include_router(attestation_router)
    app.include_router(config_control_router)
    app.include_router(billing_router)
    app.include_router(audit_router)
    app.include_router(compliance_router)
    app.include_router(compliance_cp_extension_router)
    app.include_router(enterprise_controls_router)
    app.include_router(exception_breakglass_router)
    app.include_router(evidence_anchors_router)
    app.include_router(auth_federation_router)
    if ai_plane_enabled():
        app.include_router(ai_plane_extension_router)
    app.include_router(planes_router)
    app.include_router(evidence_index_router)
    app.include_router(keys_router)
    app.include_router(forensics_router)
    app.include_router(agent_enrollment_router)
    app.include_router(agent_tokens_router)
    app.include_router(agent_phase2_router)
    app.include_router(connectors_control_plane_router)
    app.include_router(control_plane_router)
    if _testing_control_tower_enabled():
        app.include_router(testing_control_tower_router)
    if _should_mount_admin_routes():
        app.include_router(agent_phase2_admin_router)
    if mission_router is not None:
        app.include_router(mission_router)
    if ring_router is not None:
        app.include_router(ring_router)
    if roe_router is not None:
        app.include_router(roe_router)
    if governance_router is not None:
        app.include_router(governance_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": app.state.service,
            "version": app.state.app_version,
        }

    @app.get("/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def health_ready() -> dict[str, Any]:
        return {"status": "ready", "dependencies": {"db": "contract"}}

    return app


_RUNTIME_APP: FastAPI | _LazyRuntimeApp | None = None


def _is_contract_generation_context() -> bool:
    return _env_bool("FG_CONTRACTS_GEN", default=False)


def _import_build_mode() -> str:
    return (os.getenv("FG_IMPORT_BUILD_MODE") or "strict").strip().lower() or "strict"


def get_app() -> FastAPI:
    global _RUNTIME_APP
    if _RUNTIME_APP is None or isinstance(_RUNTIME_APP, _LazyRuntimeApp):
        _RUNTIME_APP = build_app()
    return _RUNTIME_APP


def create_app() -> FastAPI:
    return build_app()


class _LazyRuntimeApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        app_instance = get_app()
        await app_instance(scope, receive, send)

    def __getattr__(self, name: str) -> Any:
        return getattr(get_app(), name)


def _module_app_binding() -> FastAPI | _LazyRuntimeApp | None:
    if _is_contract_generation_context():
        return None

    mode = _import_build_mode()
    if mode == "soft":
        return _LazyRuntimeApp()

    if _env_bool("FG_BUILD_APP_ON_IMPORT", default=False):
        return get_app()

    return _LazyRuntimeApp()


app = _module_app_binding()
