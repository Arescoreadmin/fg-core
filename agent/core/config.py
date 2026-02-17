from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from typing import Any

from agent.core.transport import TransportClient


SAFE_TASKS = {"ping", "self_test"}
PINNED_REFRESH_REASON = "config_refresh_requires_pinned_transport"
SIG_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentConfig:
    config_hash: str
    config_sig: str | None
    tenant_id: str
    policy: dict[str, Any]
    fetched_at: float
    canonical_json: str


class ConfigManager:
    def __init__(
        self,
        *,
        hmac_key: str | None = None,
        hmac_keys: list[str] | None = None,
    ) -> None:
        self._current: AgentConfig | None = None
        self._last_error: str | None = None
        self._hmac_keys, self._keyring_parse_error = self._resolve_hmac_keys(
            hmac_key=hmac_key, hmac_keys=hmac_keys
        )

    @staticmethod
    def _resolve_hmac_keys(
        *,
        hmac_key: str | None,
        hmac_keys: list[str] | None,
    ) -> tuple[tuple[str, ...], str | None]:
        parse_error: str | None = None
        explicit_source = hmac_keys or []
        explicit = [k for k in explicit_source if isinstance(k, str) and k.strip()]
        if len(explicit) != len(explicit_source):
            parse_error = "config_hmac_keyring_parse_failed"
        if hmac_key is not None and hmac_key.strip():
            explicit.insert(0, hmac_key.strip())
        if explicit:
            return tuple(dict.fromkeys(explicit)), parse_error

        env_keys: list[str] = []
        current = (os.getenv("FG_CONFIG_HMAC_KEY_CURRENT") or "").strip()
        previous = (os.getenv("FG_CONFIG_HMAC_KEY_PREV") or "").strip()
        legacy = (os.getenv("FG_CONFIG_HMAC_KEY") or "").strip()
        csv_keys = (os.getenv("FG_CONFIG_HMAC_KEYS") or "").strip()
        if previous and not current and not legacy and not csv_keys:
            parse_error = "config_hmac_current_required_for_signing"
        if current:
            env_keys.append(current)
        if previous:
            env_keys.append(previous)
        if legacy:
            env_keys.append(legacy)
        if csv_keys:
            env_keys.extend(k.strip() for k in csv_keys.split(",") if k.strip())

        if (os.getenv("FG_CONFIG_HMAC_KEYS") or "").strip() and not env_keys:
            parse_error = "config_hmac_keyring_parse_failed"
        return tuple(dict.fromkeys(env_keys)), parse_error

    @property
    def keyring_parse_error(self) -> str | None:
        return self._keyring_parse_error

    @property
    def keyring_degraded(self) -> bool:
        return self._keyring_parse_error is not None

    @property
    def signing_key_id(self) -> str | None:
        if not self._hmac_keys:
            return None
        return "k0"

    def sign_canonical_json(self, canonical_json: str) -> tuple[str, str]:
        if not self._hmac_keys:
            raise ConfigError("hmac_signing_not_configured")
        sig = hmac.new(
            self._hmac_keys[0].encode("utf-8"),
            canonical_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return sig, "k0"

    @property
    def degraded(self) -> bool:
        return self._current is None

    @property
    def config_hash(self) -> str | None:
        return None if self._current is None else self._current.config_hash

    def load_local(self, payload: dict[str, Any], *, fetched_at: float) -> AgentConfig:
        config = self._validate(payload, fetched_at=fetched_at)
        self._current = config
        self._last_error = None
        return config

    def refresh(
        self,
        transport: TransportClient,
        path: str,
        *,
        now: float,
        require_pinned_transport: bool = True,
    ) -> AgentConfig:
        if require_pinned_transport and not transport.pinned_endpoint:
            self._last_error = PINNED_REFRESH_REASON
            raise ConfigError(self._last_error)
        response = transport.request("GET", path, correlation_id=None)
        if response.status_code != 200:
            raise ConfigError("config_refresh_failed")
        config = self._validate(response.json_body, fetched_at=now)
        self._current = config
        self._last_error = None
        return config

    def _validate(self, payload: dict[str, Any], *, fetched_at: float) -> AgentConfig:
        if not isinstance(payload, dict):
            self._last_error = "config_not_object"
            raise ConfigError(self._last_error)
        if not payload.get("config_hash"):
            self._last_error = "missing_config_hash"
            raise ConfigError(self._last_error)
        if not isinstance(payload.get("tenant_id"), str) or not payload["tenant_id"]:
            self._last_error = "invalid_tenant_id"
            raise ConfigError(self._last_error)

        policy = payload.get("policy")
        if not isinstance(policy, dict):
            self._last_error = "invalid_policy"
            raise ConfigError(self._last_error)

        unsigned_payload = dict(payload)
        provided_hash = str(unsigned_payload.pop("config_hash"))
        provided_sig = unsigned_payload.pop("config_sig", None)
        if provided_sig is not None and not isinstance(provided_sig, str):
            self._last_error = "invalid_config_sig"
            raise ConfigError(self._last_error)

        canonical_json = json.dumps(
            unsigned_payload, sort_keys=True, separators=(",", ":")
        )

        digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        if digest != provided_hash:
            self._last_error = "integrity_hash_mismatch"
            raise ConfigError(self._last_error)

        if provided_sig is not None and not SIG_HEX_RE.fullmatch(provided_sig):
            self._last_error = "invalid_config_sig_format"
            raise ConfigError(self._last_error)

        if self._keyring_parse_error:
            self._last_error = self._keyring_parse_error
            raise ConfigError(self._last_error)

        if self._hmac_keys:
            if not provided_sig:
                self._last_error = "missing_config_sig"
                raise ConfigError(self._last_error)
            if not any(
                hmac.compare_digest(
                    provided_sig,
                    hmac.new(
                        key.encode("utf-8"),
                        canonical_json.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest(),
                )
                for key in self._hmac_keys
            ):
                self._last_error = "config_sig_mismatch"
                raise ConfigError(self._last_error)

        return AgentConfig(
            config_hash=provided_hash,
            config_sig=provided_sig,
            tenant_id=payload["tenant_id"],
            policy=policy,
            fetched_at=fetched_at,
            canonical_json=canonical_json,
        )

    def policy_allows_task(self, task_type: str) -> bool:
        if self._current is None:
            return task_type in SAFE_TASKS
        allowed = self._current.policy.get("allowed_tasks", [])
        if not isinstance(allowed, list):
            return False
        return task_type in set(allowed)

    def policy_allows_network(self) -> bool:
        if self._current is None:
            return False
        return bool(self._current.policy.get("allow_outbound_network", False))

    def requires_valid_config(self, task_type: str) -> bool:
        return task_type not in SAFE_TASKS

    def can_execute(
        self, task_type: str, *, refresh_transport_pinned: bool = False
    ) -> bool:
        if task_type == "config_refresh":
            if self._current is None:
                return bool(refresh_transport_pinned)
            return self.policy_allows_task(task_type) and bool(refresh_transport_pinned)
        if self._current is None:
            return task_type in SAFE_TASKS
        return self.policy_allows_task(task_type)

    def config_age_seconds(self, *, now: float) -> float | None:
        if self._current is None:
            return None
        return max(0.0, now - self._current.fetched_at)

    def last_error(self) -> str | None:
        return self._last_error
