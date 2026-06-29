"""tools/ci/context_registry.py

Context Registry — declarative source of truth for FrostGate Smart Gate validation.

Parses tools/ci/context_registry.yaml and provides a typed API used by fg_smart_gate.py.
Adding a new authority requires only a YAML entry; no Python changes are needed.

Public API
----------
    registry = ContextRegistry.load()
    contexts = registry.detect_contexts(changed_files)
    tests    = registry.collect_tests(contexts)
    gates    = registry.collect_gates(changed_files)
    expanded = registry.expand_dependencies(contexts)
    summary  = registry.summarize()
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REGISTRY_PATH = Path(__file__).parent / "context_registry.yaml"
SUPPORTED_GATES: frozenset[str] = frozenset(
    {"authority", "contract", "privacy", "security"}
)


class RegistryValidationError(ValueError):
    """Raised when the registry YAML fails structural or semantic validation."""


@dataclass(frozen=True)
class ContextEntry:
    name: str
    description: str
    owners: tuple[str, ...]
    paths: tuple[str, ...]
    tests: tuple[str, ...]
    dependencies: tuple[str, ...]
    gates: dict[str, bool]
    smoke_enabled: bool


@dataclass(frozen=True)
class GlobalConfig:
    always_tests: tuple[str, ...]
    always_gates: tuple[tuple[str, ...], ...]
    privacy_paths: tuple[str, ...]
    contract_paths: tuple[str, ...]


@dataclass(frozen=True)
class GateCommands:
    privacy: tuple[str, ...]
    contract: tuple[str, ...]


class ContextRegistry:
    """Parsed and validated representation of context_registry.yaml."""

    def __init__(
        self,
        version: int,
        global_config: GlobalConfig,
        gate_commands: GateCommands,
        contexts: dict[str, ContextEntry],
        raw: dict[str, Any],
    ) -> None:
        self._version = version
        self._global = global_config
        self._gate_commands = gate_commands
        self._contexts = contexts
        self._raw = raw

    # ── Loading ────────────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: Path | None = None) -> ContextRegistry:
        registry_path = path or REGISTRY_PATH
        try:
            text = registry_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RegistryValidationError(
                f"Cannot read registry at {registry_path}: {exc}"
            ) from exc

        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise RegistryValidationError(f"Malformed YAML in registry: {exc}") from exc

        if not isinstance(raw, dict):
            raise RegistryValidationError(
                "Registry must be a YAML mapping at the top level"
            )

        return cls._parse_and_validate(raw)

    @classmethod
    def _parse_and_validate(cls, raw: dict[str, Any]) -> ContextRegistry:
        version = cls._require_int(raw, "version", "<root>")

        global_raw = raw.get("global")
        if not isinstance(global_raw, dict):
            raise RegistryValidationError(
                "Registry is missing required 'global' section"
            )
        global_config = cls._parse_global(global_raw)

        gate_commands_raw = raw.get("gate_commands", {})
        if not isinstance(gate_commands_raw, dict):
            raise RegistryValidationError("'gate_commands' must be a mapping")
        gate_commands = cls._parse_gate_commands(gate_commands_raw)

        contexts_raw = raw.get("contexts")
        if not isinstance(contexts_raw, dict):
            raise RegistryValidationError(
                "Registry is missing required 'contexts' section"
            )
        if not contexts_raw:
            raise RegistryValidationError(
                "Registry 'contexts' section must not be empty"
            )

        contexts = cls._parse_contexts(contexts_raw)
        cls._validate_dependencies(contexts)
        cls._check_circular_dependencies(contexts)

        return cls(version, global_config, gate_commands, contexts, raw)

    # ── Section parsers ────────────────────────────────────────────────────

    @classmethod
    def _parse_global(cls, raw: dict[str, Any]) -> GlobalConfig:
        always_tests = cls._string_list(raw, "always_tests", "global")
        always_gates_raw = raw.get("always_gates", [])
        if not isinstance(always_gates_raw, list):
            raise RegistryValidationError("global.always_gates must be a list")
        always_gates: tuple[tuple[str, ...], ...] = tuple(
            tuple(str(tok) for tok in cmd) for cmd in always_gates_raw
        )
        privacy_paths = cls._string_list(raw, "privacy_paths", "global")
        contract_paths = cls._string_list(raw, "contract_paths", "global")
        return GlobalConfig(
            always_tests=always_tests,
            always_gates=always_gates,
            privacy_paths=privacy_paths,
            contract_paths=contract_paths,
        )

    @classmethod
    def _parse_gate_commands(cls, raw: dict[str, Any]) -> GateCommands:
        privacy_raw = raw.get("privacy", [])
        contract_raw = raw.get("contract", [])
        return GateCommands(
            privacy=tuple(str(t) for t in privacy_raw) if privacy_raw else (),
            contract=tuple(str(t) for t in contract_raw) if contract_raw else (),
        )

    @classmethod
    def _parse_contexts(cls, raw: dict[str, Any]) -> dict[str, ContextEntry]:
        contexts: dict[str, ContextEntry] = {}
        seen_paths: dict[str, str] = {}
        seen_tests: dict[str, str] = {}

        for name, ctx_raw in raw.items():
            if not isinstance(ctx_raw, dict):
                raise RegistryValidationError(
                    f"Context '{name}' must be a mapping, got {type(ctx_raw).__name__}"
                )
            entry = cls._parse_context_entry(name, ctx_raw)

            for p in entry.paths:
                if p in seen_paths:
                    raise RegistryValidationError(
                        f"Duplicate path '{p}' in context '{name}' "
                        f"(already owned by '{seen_paths[p]}')"
                    )
                seen_paths[p] = name

            for t in entry.tests:
                if t in seen_tests:
                    raise RegistryValidationError(
                        f"Duplicate test '{t}' in context '{name}' "
                        f"(already owned by '{seen_tests[t]}')"
                    )
                seen_tests[t] = name

            contexts[name] = entry

        return contexts

    @classmethod
    def _parse_context_entry(cls, name: str, raw: dict[str, Any]) -> ContextEntry:
        description = raw.get("description", "")
        if not isinstance(description, str):
            raise RegistryValidationError(
                f"Context '{name}': description must be a string"
            )

        owners_raw = raw.get("owners", [])
        if not isinstance(owners_raw, list):
            raise RegistryValidationError(f"Context '{name}': owners must be a list")
        owners = tuple(str(o) for o in owners_raw)

        paths = cls._string_list(raw, "paths", f"context '{name}'")
        if not paths:
            raise RegistryValidationError(f"Context '{name}': paths must not be empty")

        tests = cls._string_list(raw, "tests", f"context '{name}'")
        if not tests:
            raise RegistryValidationError(f"Context '{name}': tests must not be empty")

        deps = cls._string_list(raw, "dependencies", f"context '{name}'")

        gates_raw = raw.get("gates", {})
        if not isinstance(gates_raw, dict):
            raise RegistryValidationError(f"Context '{name}': gates must be a mapping")
        unknown = set(gates_raw.keys()) - SUPPORTED_GATES
        if unknown:
            raise RegistryValidationError(
                f"Context '{name}': unknown gate type(s): {sorted(unknown)}. "
                f"Supported: {sorted(SUPPORTED_GATES)}"
            )
        gates: dict[str, bool] = {
            g: bool(gates_raw.get(g, False)) for g in SUPPORTED_GATES
        }

        smoke_raw = raw.get("smoke", {})
        smoke_enabled = (
            bool(smoke_raw.get("enabled", False))
            if isinstance(smoke_raw, dict)
            else False
        )

        return ContextEntry(
            name=name,
            description=description,
            owners=owners,
            paths=paths,
            tests=tests,
            dependencies=deps,
            gates=gates,
            smoke_enabled=smoke_enabled,
        )

    # ── Validation ─────────────────────────────────────────────────────────

    @staticmethod
    def _validate_dependencies(contexts: dict[str, ContextEntry]) -> None:
        for name, entry in contexts.items():
            for dep in entry.dependencies:
                if dep not in contexts:
                    raise RegistryValidationError(
                        f"Context '{name}' declares dependency '{dep}' "
                        f"which is not defined in the registry"
                    )
            if name in entry.dependencies:
                raise RegistryValidationError(
                    f"Context '{name}' declares itself as a dependency"
                )

    @staticmethod
    def _check_circular_dependencies(contexts: dict[str, ContextEntry]) -> None:
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {n: WHITE for n in contexts}

        def dfs(name: str, path: list[str]) -> None:
            color[name] = GRAY
            for dep in sorted(contexts[name].dependencies):
                if color[dep] == GRAY:
                    cycle_start = path.index(dep)
                    cycle = " → ".join(path[cycle_start:] + [dep])
                    raise RegistryValidationError(
                        f"Circular dependency detected: {cycle}"
                    )
                if color[dep] == WHITE:
                    dfs(dep, path + [dep])
            color[name] = BLACK

        for name in sorted(contexts):
            if color[name] == WHITE:
                dfs(name, [name])

    # ── Public API ─────────────────────────────────────────────────────────

    def detect_contexts(self, changed_files: list[str]) -> set[str]:
        """Return context names whose paths overlap with changed_files."""
        detected: set[str] = set()
        for name, entry in self._contexts.items():
            for f in changed_files:
                if any(f == p or f.startswith(p) for p in entry.paths):
                    detected.add(name)
                    break
        return detected

    def expand_dependencies(self, contexts: set[str]) -> set[str]:
        """Return contexts plus all transitive dependencies, BFS order."""
        expanded = set(contexts)
        queue = sorted(contexts)
        while queue:
            name = queue.pop(0)
            if name not in self._contexts:
                continue
            for dep in sorted(self._contexts[name].dependencies):
                if dep not in expanded:
                    expanded.add(dep)
                    queue.append(dep)
        return expanded

    def collect_tests(self, contexts: set[str]) -> list[str]:
        """Return deduplicated ordered tests for contexts and their transitive deps."""
        expanded = self.expand_dependencies(contexts)
        seen: set[str] = set()
        tests: list[str] = []
        for name in sorted(expanded):
            if name not in self._contexts:
                continue
            for t in self._contexts[name].tests:
                if t not in seen:
                    tests.append(t)
                    seen.add(t)
        return tests

    def collect_gates(self, changed_files: list[str]) -> list[list[str]]:
        """Return gate commands whose trigger paths match changed_files."""
        gates: list[list[str]] = []

        if self._gate_commands.privacy and any(
            any(f == p or f.startswith(p) for p in self._global.privacy_paths)
            for f in changed_files
        ):
            gates.append(list(self._gate_commands.privacy))

        if self._gate_commands.contract and any(
            any(f == p or f.startswith(p) for p in self._global.contract_paths)
            for f in changed_files
        ):
            gates.append(list(self._gate_commands.contract))

        return gates

    def summarize(self) -> str:
        lines = [
            f"ContextRegistry v{self._version}",
            f"  Contexts : {len(self._contexts)}",
            f"  Always tests : {len(self._global.always_tests)}",
            f"  Always gates : {len(self._global.always_gates)}",
        ]
        for name in sorted(self._contexts):
            entry = self._contexts[name]
            deps = list(entry.dependencies) or ["—"]
            lines.append(
                f"  [{name}]  paths={len(entry.paths)}  "
                f"tests={len(entry.tests)}  deps={deps}"
            )
        return "\n".join(lines)

    def digest(self) -> str:
        """SHA-256 hex digest of the canonical serialised registry."""
        canonical = json.dumps(self._raw, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def version(self) -> int:
        return self._version

    @property
    def global_config(self) -> GlobalConfig:
        return self._global

    @property
    def gate_commands(self) -> GateCommands:
        return self._gate_commands

    @property
    def contexts(self) -> dict[str, ContextEntry]:
        return dict(self._contexts)

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _string_list(d: dict[str, Any], key: str, section: str) -> tuple[str, ...]:
        val = d.get(key, [])
        if not isinstance(val, list):
            raise RegistryValidationError(
                f"{section}.{key} must be a list, got {type(val).__name__}"
            )
        for i, item in enumerate(val):
            if not isinstance(item, str):
                raise RegistryValidationError(
                    f"{section}.{key}[{i}] must be a string, got {type(item).__name__}"
                )
        return tuple(val)

    @staticmethod
    def _require_int(d: dict[str, Any], key: str, section: str) -> int:
        val = d.get(key)
        if val is None:
            raise RegistryValidationError(
                f"'{section}' is missing required field '{key}'"
            )
        if not isinstance(val, int) or isinstance(val, bool):
            raise RegistryValidationError(
                f"'{section}.{key}' must be an integer, got {type(val).__name__}"
            )
        return val
