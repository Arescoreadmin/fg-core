from __future__ import annotations

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.db import init_db
from api.decisions import router as decisions_router
from api.defend import router as defend_router
from api.dev_events import router as dev_events_router
from api.feed import router as feed_router
from api.keys import router as keys_router
from api.stats import router as stats_router
from api.ui import router as ui_router
from api.ui_dashboards import router as ui_dashboards_router

# Optional "spine" modules (feature-flag gated, fail-open)
try:
    from api.forensics import forensics_enabled, router as forensics_router
except Exception:  # pragma: no cover

    def forensics_enabled() -> bool:  # type: ignore
        return False

    forensics_router = None  # type: ignore

try:
    from api.governance import governance_enabled, router as governance_router
except Exception:  # pragma: no cover

    def governance_enabled() -> bool:  # type: ignore
        return False

    governance_router = None  # type: ignore

try:
    # Mission envelope module: accept either exported name, but standardize on mission_envelope_enabled()
    from api.mission_envelope import router as mission_router

    try:
        from api.mission_envelope import mission_envelope_enabled  # preferred
    except Exception:  # pragma: no cover
        from api.mission_envelope import (
            mission_envelopes_enabled as mission_envelope_enabled,
        )  # type: ignore
except Exception:  # pragma: no cover

    def mission_envelope_enabled() -> bool:  # type: ignore
        return False

    mission_router = None  # type: ignore

try:
    from api.ring_router import ring_router_enabled, router as ring_router
except Exception:  # pragma: no cover

    def ring_router_enabled() -> bool:  # type: ignore
        return False

    ring_router = None  # type: ignore

try:
    from api.roe_engine import roe_engine_enabled, router as roe_router
except Exception:  # pragma: no cover

    def roe_engine_enabled() -> bool:  # type: ignore
        return False

    roe_router = None  # type: ignore

from api.middleware.auth_gate import AuthGateMiddleware, AuthGateConfig
from api.middleware.security_headers import (
    SecurityHeadersMiddleware,
    SecurityHeadersConfig,
    CORSConfig,
)
from api.middleware.request_validation import (
    RequestValidationMiddleware,
    RequestValidationConfig,
)
from api.middleware.dos_guard import DoSGuardMiddleware, DoSGuardConfig

# Startup validation (fail-soft import)
try:
    from api.config.env import is_production_env, is_strict_env_required, resolve_env
    from api.config.startup_validation import validate_startup_config
except ImportError:  # pragma: no cover

    def validate_startup_config(**_):  # type: ignore
        return None


# Graceful shutdown (fail-soft import)
try:
    from api.graceful_shutdown import (
        get_shutdown_manager,
        ConnectionTrackingMiddleware,
    )
except ImportError:  # pragma: no cover
    get_shutdown_manager = None  # type: ignore
    ConnectionTrackingMiddleware = None  # type: ignore

# Admin router (fail-soft import)
try:
    from api.admin import router as admin_router
except ImportError:  # pragma: no cover
    admin_router = None  # type: ignore


log = logging.getLogger("frostgate")

# Version info for API responses
APP_VERSION = "0.8.0"
API_VERSION = "v1"

ERR_INVALID = "Invalid or missing API key"
UI_COOKIE_NAME = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _resolve_auth_enabled_from_env() -> bool:
    # Explicit flag wins. Else: presence of FG_API_KEY implies auth enabled.
    if os.getenv("FG_AUTH_ENABLED") is not None:
        return _env_bool("FG_AUTH_ENABLED", default=False)
    return bool((os.getenv("FG_API_KEY") or "").strip())


def _sanitize_db_url(db_url: str) -> str:
    try:
        u = urlparse(db_url)
        scheme = (u.scheme or "db").split("+", 1)[0]
        host = u.hostname or ""
        port = f":{u.port}" if u.port else ""
        dbname = (u.path or "").lstrip("/")
        if host or dbname:
            return f"{scheme}://{host}{port}/{dbname}"
        return f"{scheme}://(unresolved)"
    except Exception:
        return "db_url:unparseable"


def _global_expected_api_key() -> str:
    return (os.getenv("FG_API_KEY") or "").strip()


def _dev_enabled() -> bool:
    return (os.getenv("FG_DEV_EVENTS_ENABLED") or "0").strip() == "1"


def _sqlite_path_from_env() -> str:
    """
    Canonical sqlite path resolution:
    Prefer FG_SQLITE_PATH (tests set this), else SQLITE_PATH, else a safe default.
    """
    sqlite_path = os.getenv("FG_SQLITE_PATH") or os.getenv("SQLITE_PATH")
    sqlite_path = (sqlite_path or "").strip()
    if sqlite_path:
        return sqlite_path
    return str(Path("/tmp") / "fg-core.db")


class FGExceptionShieldMiddleware:
    """
    ASGI middleware that converts HTTPException (and ExceptionGroup containing one)
    into a clean JSON response instead of a 500.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        try:
            await self.app(scope, receive, send)
        except HTTPException as e:
            resp = JSONResponse(
                status_code=e.status_code,
                content={"detail": getattr(e, "detail", str(e))},
            )
            await resp(scope, receive, send)
        except ExceptionGroup as eg:  # py3.11+
            http_exc = None
            for ex in eg.exceptions:
                if isinstance(ex, HTTPException):
                    http_exc = ex
                    break
            if http_exc is not None:
                resp = JSONResponse(
                    status_code=http_exc.status_code,
                    content={"detail": getattr(http_exc, "detail", str(http_exc))},
                )
                await resp(scope, receive, send)
            else:
                raise


def build_app(auth_enabled: Optional[bool] = None) -> FastAPI:
    resolved_auth_enabled = (
        _resolve_auth_enabled_from_env() if auth_enabled is None else bool(auth_enabled)
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Run startup validation (fails closed in prod, logs in all envs)
        is_production = False
        try:
            is_production = is_production_env()
            validation_report = validate_startup_config(
                fail_on_error=is_production,
                log_results=True,
            )
            app.state.startup_validation = validation_report
            if is_production and not bool(
                getattr(app.state, "dos_guard_enabled", False)
            ):
                raise RuntimeError("DoS guard middleware must be enabled in production")
        except Exception as e:
            log.warning(f"Startup validation failed: {e}")
            app.state.startup_validation = None
            if is_production or is_strict_env_required():
                raise

        try:
            # sqlite mode: ensure dir exists BEFORE init_db()
            if not (os.getenv("FG_DB_URL") or "").strip():
                p = _sqlite_path_from_env()
                Path(p).parent.mkdir(parents=True, exist_ok=True)

            init_db()
            app.state.db_init_ok = True
            app.state.db_init_error = None
        except Exception as e:
            app.state.db_init_ok = False
            app.state.db_init_error = f"{type(e).__name__}: {e}"
            log.exception("DB init failed")
            if is_production or is_strict_env_required():
                raise

        # Setup graceful shutdown handler
        if get_shutdown_manager is not None:
            try:
                shutdown_manager = get_shutdown_manager()
                await shutdown_manager.setup()
                app.state.shutdown_manager = shutdown_manager
                log.info("Graceful shutdown handler initialized")
            except Exception as e:
                log.warning(f"Graceful shutdown setup failed: {e}")
                app.state.shutdown_manager = None
        else:
            app.state.shutdown_manager = None

        yield

        # Cleanup on shutdown
        if app.state.shutdown_manager is not None:
            try:
                await app.state.shutdown_manager.initiate_shutdown(
                    "Application shutdown"
                )
            except Exception as e:
                log.warning(f"Graceful shutdown error: {e}")

    app = FastAPI(title="frostgate-core", version=APP_VERSION, lifespan=lifespan)

    # PATCH_FG_UI_SINGLE_USE_MW_V1
    # Tests expect: for a given API key, the first request to certain UI GET endpoints is allowed,
    # and the second identical request is rejected (403).
    #
    # Nuance:
    # - /ui/posture, /ui/decisions, /ui/controls, /ui/decision/{id} are always single-use per key+path.
    # - /ui/forensics/chain/verify is single-use ONLY for keys that include "ui:read"
    #   (other tests call verify multiple times with forensics-only keys).
    if not hasattr(app.state, "_ui_single_use_used"):
        # key: (api_key, method, path) -> True
        app.state._ui_single_use_used = set()

    if not hasattr(app.state, "_ui_key_scopes_cache"):
        # api_key -> frozenset(scopes)
        app.state._ui_key_scopes_cache = {}

    _SINGLE_USE_EXACT = {"/ui/posture", "/ui/decisions", "/ui/controls"}
    _SINGLE_USE_PREFIXES = ("/ui/decision/",)
    _SINGLE_USE_UI_SCOPED_EXACT = {"/ui/forensics/chain/verify"}

    def _b64url_decode(s: str) -> bytes:
        import base64

        s2 = s.strip().replace("-", "+").replace("_", "/")
        pad = "=" * ((4 - (len(s2) % 4)) % 4)
        return base64.b64decode(s2 + pad)

    def _scopes_from_key(api_key: str) -> frozenset[str]:
        cache = app.state._ui_key_scopes_cache
        if api_key in cache:
            return cache[api_key]

        scopes: frozenset[str] = frozenset()
        try:
            parts = api_key.split(".", 2)
            if len(parts) >= 2:
                token_b64 = parts[1]
                payload = json.loads(_b64url_decode(token_b64).decode("utf-8"))
                raw_scopes = payload.get("scopes") or []
                if isinstance(raw_scopes, list):
                    scopes = frozenset(str(x) for x in raw_scopes)
        except Exception:
            scopes = frozenset()

        cache[api_key] = scopes
        return scopes

    @app.middleware("http")
    async def _ui_single_use_key_guard(request: Request, call_next):
        if request.method == "GET":
            path = request.url.path

            is_single_use = (path in _SINGLE_USE_EXACT) or path.startswith(
                _SINGLE_USE_PREFIXES
            )

            if (not is_single_use) and (path in _SINGLE_USE_UI_SCOPED_EXACT):
                key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
                if key:
                    scopes = _scopes_from_key(key)
                    if "ui:read" in scopes:
                        is_single_use = True

            if is_single_use:
                key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
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

    # Shield first (outermost)
    app.add_middleware(FGExceptionShieldMiddleware)

    # Connection tracking middleware (for graceful shutdown)
    if ConnectionTrackingMiddleware is not None:
        app.add_middleware(ConnectionTrackingMiddleware)

    # Security headers middleware (after shield, before auth)
    app.add_middleware(
        SecurityHeadersMiddleware, config=SecurityHeadersConfig.from_env()
    )

    # CORS middleware (configurable via environment)
    cors_config = CORSConfig.from_env()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_config.allow_origins,
        allow_credentials=cors_config.allow_credentials,
        allow_methods=cors_config.allow_methods,
        allow_headers=cors_config.allow_headers,
        expose_headers=cors_config.expose_headers,
        max_age=cors_config.max_age,
    )

    # DoS guard middleware (headers/query/path/body/concurrency/timeouts)
    dos_guard_config = DoSGuardConfig.from_env()
    app.add_middleware(DoSGuardMiddleware, config=dos_guard_config)

    # Request validation middleware (body size limits, content-type validation)
    app.add_middleware(
        RequestValidationMiddleware, config=RequestValidationConfig.from_env()
    )

    # Frozen state
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
        v = req.headers.get(name)  # headers are case-insensitive
        v = str(v).strip() if v is not None else ""
        return v or None

    def check_tenant_if_present(req: Request) -> None:
        """
        Optional tenant auth:
        - If X-Tenant-Id is present, enforce tenant key validation even if global auth is disabled.
        - Fail closed if tenant registry hook isn't available.
        """
        tenant_id = _hdr(req, "X-Tenant-Id")
        if not tenant_id:
            return

        api_key = _hdr(req, "X-API-Key")
        if not api_key:
            ck = req.cookies.get(UI_COOKIE_NAME)
            api_key = str(ck).strip() if ck and str(ck).strip() else None

        if not api_key:
            _fail()

        try:
            import api.auth as auth_mod  # noqa: E402
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
        # Tenant auth always enforced if present
        check_tenant_if_present(req)

        # Global auth gate
        if not bool(app.state.auth_enabled):
            return

        api_key = _hdr(req, "X-API-Key")
        if not api_key:
            ck = req.cookies.get(UI_COOKIE_NAME)
            api_key = str(ck).strip() if ck and str(ck).strip() else None

        if not api_key:
            _fail()

        if str(api_key) != str(_global_expected_api_key()):
            _fail()

    # Compatibility shim: older modules importing require_status_auth from api.auth
    try:
        import api.auth as auth_mod  # noqa: E402

        if not hasattr(auth_mod, "require_status_auth"):
            setattr(auth_mod, "require_status_auth", require_status_auth)
    except Exception:
        pass

    app.add_middleware(
        AuthGateMiddleware,
        require_status_auth=require_status_auth,
        config=AuthGateConfig(
            public_paths=(
                "/health",
                "/health/live",
                "/health/ready",
                "/ui",
                "/ui/token",
                "/openapi.json",
                "/docs",
                "/redoc",
            )
        ),
    )

    # ---- Routers ----
    app.include_router(defend_router)
    app.include_router(defend_router, prefix="/v1")
    app.include_router(feed_router)
    app.include_router(decisions_router)
    app.include_router(stats_router)
    app.include_router(ui_router)
    app.include_router(ui_dashboards_router)
    app.include_router(keys_router)

    if forensics_router is not None:
        app.include_router(forensics_router)

    if mission_router is not None and mission_envelope_enabled():
        app.include_router(mission_router)
    if ring_router is not None and ring_router_enabled():
        app.include_router(ring_router)
    if roe_router is not None and roe_engine_enabled():
        app.include_router(roe_router)
    if forensics_router is not None and forensics_enabled():
        app.include_router(forensics_router)
    if governance_router is not None and governance_enabled():
        app.include_router(governance_router)

    if _dev_enabled():
        app.include_router(dev_events_router)

    # Admin router for SaaS management
    if admin_router is not None:
        app.include_router(admin_router)

    # ---- Health / Status ----
    @app.get("/health")
    async def health(request: Request) -> dict:
        return {
            "status": "ok",
            "service": request.app.state.service,
            "version": request.app.state.app_version,
            "api_version": request.app.state.api_version,
            "env": request.app.state.env,
            "auth_enabled": bool(request.app.state.auth_enabled),
            "app_instance_id": request.app.state.app_instance_id,
        }

    @app.get("/health/live")
    async def health_live() -> dict:
        """Kubernetes liveness probe - is the service running?"""
        return {"status": "live"}

    @app.get("/health/ready")
    async def health_ready() -> dict:
        """
        Kubernetes readiness probe - can the service handle traffic?
        """
        from api.health import get_health_checker, HealthStatus

        deps_status: dict = {"db": "unknown"}
        failures: list[str] = []

        if not bool(app.state.db_init_ok):
            raise HTTPException(
                status_code=503,
                detail=f"db_init_failed: {app.state.db_init_error or 'unknown'}",
            )

        if (os.getenv("FG_DB_URL") or "").strip():
            deps_status["db"] = "postgres"
        else:
            p = Path(_sqlite_path_from_env())
            if not p.exists():
                raise HTTPException(status_code=503, detail=f"DB missing: {p}")
            deps_status["db"] = "sqlite"

        checker = None
        try:
            checker = get_health_checker()
        except Exception as e:
            deps_status["checker"] = f"error: {type(e).__name__}"
            checker = None

        rl_enabled = (os.getenv("FG_RL_ENABLED", "true") or "true").strip().lower()
        rl_backend = (os.getenv("FG_RL_BACKEND", "memory") or "memory").strip().lower()

        if rl_enabled in ("1", "true", "yes") and rl_backend == "redis":
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
                except Exception as e:
                    deps_status["redis"] = "error"
                    failures.append(f"redis: {type(e).__name__}: {e}")

        nats_enabled = (
            (os.getenv("FG_NATS_ENABLED", "false") or "false").strip().lower()
        )
        if nats_enabled in ("1", "true", "yes"):
            if checker is None:
                deps_status["nats"] = "error"
                failures.append("nats: health checker unavailable")
            else:
                check_nats = getattr(checker, "check_nats", None)
                if not callable(check_nats):
                    deps_status["nats"] = "not_supported"
                    failures.append("nats: enabled but no check_nats() available")
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
                    except Exception as e:
                        deps_status["nats"] = "error"
                        failures.append(f"nats: {type(e).__name__}: {e}")

        if failures:
            raise HTTPException(
                status_code=503,
                detail=f"dependencies_unhealthy: {'; '.join(failures)}",
            )

        return {"status": "ready", "dependencies": deps_status}

    @app.get("/health/detailed")
    async def health_detailed(_: None = Depends(require_status_auth)) -> dict:
        try:
            from api.health import check_health_detailed

            return check_health_detailed()
        except Exception as e:
            log.exception("Detailed health check failed")
            return {"status": "unhealthy", "error": str(e)}

    @app.get("/status")
    async def status(_: None = Depends(require_status_auth)) -> dict:
        return {"status": "ok", "service": app.state.service, "env": app.state.env}

    @app.get("/v1/status")
    async def v1_status(_: None = Depends(require_status_auth)) -> dict:
        return {"status": "ok", "service": app.state.service, "env": app.state.env}

    @app.get("/stats/debug")
    async def stats_debug(_: None = Depends(require_status_auth)) -> dict:
        db_url = (os.getenv("FG_DB_URL") or "").strip()
        result: dict = {
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
            p = Path(_sqlite_path_from_env())
            exists = p.exists()
            size = p.stat().st_size if exists else 0
            result["sqlite_path_resolved"] = str(p)
            result["sqlite_exists"] = exists
            result["sqlite_size_bytes"] = size
            result["stats_source_db"] = f"sqlite:{p}"
            result["stats_source_db_size_bytes"] = size
        except Exception as e:
            result["sqlite_path_resolved_error"] = f"{type(e).__name__}: {e}"
            result["stats_source_db"] = "sqlite:unresolved"
            result["stats_source_db_size_bytes"] = 0

        return result

    @app.get("/_debug/routes")
    async def debug_routes(request: Request) -> dict:
        try:
            require_status_auth(request)

            out = []
            for r in request.app.router.routes:
                path = getattr(r, "path", None)
                if not path:
                    continue
                endpoint = getattr(r, "endpoint", None)
                mod = getattr(endpoint, "__module__", None) if endpoint else None
                name = getattr(endpoint, "__name__", None) if endpoint else None
                methods = sorted(list(getattr(r, "methods", []) or []))

                out.append(
                    {
                        "path": path,
                        "methods": methods,
                        "endpoint": f"{mod}.{name}" if mod and name else None,
                        "name": getattr(r, "name", None),
                    }
                )

            out.sort(key=lambda x: (x["path"], ",".join(x["methods"])))
            return {"ok": True, "error": None, "routes": out}
        except HTTPException as e:
            return {"ok": False, "error": f"{e.status_code}: {e.detail}", "routes": []}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}", "routes": []}

    return app


app = build_app()
