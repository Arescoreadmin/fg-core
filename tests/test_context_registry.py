"""tests/test_context_registry.py

Tests for tools/ci/context_registry.py — ContextRegistry validation, detection,
dependency expansion, gate collection, and serialisation.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tools.ci.context_registry import (
    ContextRegistry,
    RegistryValidationError,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_BASE = {
    "version": 1,
    "global": {
        "always_tests": ["tests/test_smoke.py"],
        "always_gates": [["python", "tools/ci/check_authority_integration.py"]],
        "privacy_paths": ["services/cgin/"],
        "contract_paths": ["api/", "services/"],
    },
    "gate_commands": {
        "privacy": ["python", "tools/ci/check_cgin_privacy.py"],
        "contract": ["make", "fg-contract"],
    },
    "contexts": {
        "alpha": {
            "description": "Alpha authority",
            "owners": ["team-a"],
            "paths": ["services/alpha/"],
            "tests": ["tests/test_alpha.py"],
            "dependencies": [],
            "gates": {
                "authority": True,
                "contract": True,
                "privacy": False,
                "security": False,
            },
            "smoke": {"enabled": True},
        },
        "beta": {
            "description": "Beta authority",
            "owners": ["team-b"],
            "paths": ["services/beta/"],
            "tests": ["tests/test_beta.py"],
            "dependencies": ["alpha"],
            "gates": {
                "authority": True,
                "contract": True,
                "privacy": False,
                "security": False,
            },
            "smoke": {"enabled": False},
        },
    },
}


def _make(overrides: dict | None = None) -> dict:
    import copy

    d = copy.deepcopy(_BASE)
    if overrides:
        d.update(overrides)
    return d


def _load_raw(raw: dict) -> ContextRegistry:
    return ContextRegistry._parse_and_validate(raw)


def _from_yaml(text: str, tmp_path: Path) -> ContextRegistry:
    p = tmp_path / "registry.yaml"
    p.write_text(textwrap.dedent(text))
    return ContextRegistry.load(p)


# ─────────────────────────────────────────────────────────────────────────────
# 1. YAML Loading
# ─────────────────────────────────────────────────────────────────────────────


class TestYAMLLoading:
    def test_load_from_real_registry(self) -> None:
        reg = ContextRegistry.load()
        assert reg.version == 1

    def test_load_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryValidationError, match="Cannot read registry"):
            ContextRegistry.load(tmp_path / "nonexistent.yaml")

    def test_load_malformed_yaml_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("key: [unclosed")
        with pytest.raises(RegistryValidationError, match="Malformed YAML"):
            ContextRegistry.load(p)

    def test_load_non_mapping_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "r.yaml"
        p.write_text("- list item")
        with pytest.raises(RegistryValidationError, match="mapping at the top level"):
            ContextRegistry.load(p)

    def test_load_valid_minimal(self) -> None:
        reg = _load_raw(_make())
        assert reg.version == 1

    def test_version_stored(self) -> None:
        reg = _load_raw(_make({"version": 2}))
        assert reg.version == 2

    def test_missing_version_raises(self) -> None:
        d = _make()
        del d["version"]
        with pytest.raises(
            RegistryValidationError, match="missing required field 'version'"
        ):
            _load_raw(d)

    def test_non_integer_version_raises(self) -> None:
        with pytest.raises(RegistryValidationError, match="must be an integer"):
            _load_raw(_make({"version": "one"}))

    def test_bool_version_rejected(self) -> None:
        with pytest.raises(RegistryValidationError, match="must be an integer"):
            _load_raw(_make({"version": True}))

    def test_missing_global_raises(self) -> None:
        d = _make()
        del d["global"]
        with pytest.raises(RegistryValidationError, match="missing required 'global'"):
            _load_raw(d)

    def test_missing_contexts_raises(self) -> None:
        d = _make()
        del d["contexts"]
        with pytest.raises(
            RegistryValidationError, match="missing required 'contexts'"
        ):
            _load_raw(d)

    def test_empty_contexts_raises(self) -> None:
        d = _make()
        d["contexts"] = {}
        with pytest.raises(RegistryValidationError, match="must not be empty"):
            _load_raw(d)

    def test_contexts_non_mapping_raises(self) -> None:
        d = _make()
        d["contexts"] = ["list"]
        with pytest.raises(
            RegistryValidationError, match="missing required 'contexts'"
        ):
            _load_raw(d)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Context Parsing
# ─────────────────────────────────────────────────────────────────────────────


class TestContextParsing:
    def _reg(self) -> ContextRegistry:
        return _load_raw(_make())

    def test_context_names_stored(self) -> None:
        reg = self._reg()
        assert set(reg.contexts.keys()) == {"alpha", "beta"}

    def test_context_description_stored(self) -> None:
        reg = self._reg()
        assert reg.contexts["alpha"].description == "Alpha authority"

    def test_context_owners_stored(self) -> None:
        reg = self._reg()
        assert reg.contexts["alpha"].owners == ("team-a",)

    def test_context_paths_stored(self) -> None:
        reg = self._reg()
        assert "services/alpha/" in reg.contexts["alpha"].paths

    def test_context_tests_stored(self) -> None:
        reg = self._reg()
        assert "tests/test_alpha.py" in reg.contexts["alpha"].tests

    def test_context_dependencies_stored(self) -> None:
        reg = self._reg()
        assert reg.contexts["beta"].dependencies == ("alpha",)

    def test_context_gates_stored(self) -> None:
        reg = self._reg()
        assert reg.contexts["alpha"].gates["authority"] is True
        assert reg.contexts["alpha"].gates["privacy"] is False

    def test_context_smoke_stored(self) -> None:
        reg = self._reg()
        assert reg.contexts["alpha"].smoke_enabled is True
        assert reg.contexts["beta"].smoke_enabled is False

    def test_empty_paths_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["paths"] = []
        with pytest.raises(RegistryValidationError, match="paths must not be empty"):
            _load_raw(d)

    def test_empty_tests_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["tests"] = []
        with pytest.raises(RegistryValidationError, match="tests must not be empty"):
            _load_raw(d)

    def test_unknown_gate_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["gates"]["bogus"] = True
        with pytest.raises(RegistryValidationError, match="unknown gate type"):
            _load_raw(d)

    def test_non_mapping_context_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"] = "string"
        with pytest.raises(RegistryValidationError, match="must be a mapping"):
            _load_raw(d)

    def test_all_supported_gates_present(self) -> None:
        reg = _load_raw(_make())
        gates = reg.contexts["alpha"].gates
        assert set(gates.keys()) == {"authority", "contract", "privacy", "security"}

    def test_missing_gates_default_false(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["gates"] = {}
        reg = _load_raw(d)
        assert all(v is False for v in reg.contexts["alpha"].gates.values())


# ─────────────────────────────────────────────────────────────────────────────
# 3. Duplicate Detection
# ─────────────────────────────────────────────────────────────────────────────


class TestDuplicateDetection:
    def test_duplicate_path_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["beta"]["paths"].append("services/alpha/")
        with pytest.raises(RegistryValidationError, match="Duplicate path"):
            _load_raw(d)

    def test_duplicate_test_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["beta"]["tests"].append("tests/test_alpha.py")
        with pytest.raises(RegistryValidationError, match="Duplicate test"):
            _load_raw(d)

    def test_same_path_same_context_allowed(self) -> None:
        # Duplicate within same context is not explicitly caught — paths is a list
        # The registry stores it as-is (no intra-context dedup required by spec).
        pass

    def test_unique_paths_ok(self) -> None:
        reg = _load_raw(_make())
        assert len(reg.contexts) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 4. Dependency Validation
# ─────────────────────────────────────────────────────────────────────────────


class TestDependencyValidation:
    def test_unknown_dependency_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["dependencies"] = ["nonexistent"]
        with pytest.raises(
            RegistryValidationError, match="not defined in the registry"
        ):
            _load_raw(d)

    def test_self_dependency_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["dependencies"] = ["alpha"]
        with pytest.raises(RegistryValidationError, match="itself as a dependency"):
            _load_raw(d)

    def test_circular_dependency_direct_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["dependencies"] = ["beta"]
        d["contexts"]["beta"]["dependencies"] = ["alpha"]
        with pytest.raises(RegistryValidationError, match="Circular dependency"):
            _load_raw(d)

    def test_circular_dependency_indirect_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["gamma"] = {
            "description": "Gamma",
            "owners": ["team-c"],
            "paths": ["services/gamma/"],
            "tests": ["tests/test_gamma.py"],
            "dependencies": ["alpha"],
            "gates": {
                "authority": False,
                "contract": False,
                "privacy": False,
                "security": False,
            },
            "smoke": {"enabled": False},
        }
        d["contexts"]["alpha"]["dependencies"] = ["gamma"]
        with pytest.raises(RegistryValidationError, match="Circular dependency"):
            _load_raw(d)

    def test_valid_chain_dep_ok(self) -> None:
        reg = _load_raw(_make())
        assert reg.contexts["beta"].dependencies == ("alpha",)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Context Detection
# ─────────────────────────────────────────────────────────────────────────────


class TestContextDetection:
    def _reg(self) -> ContextRegistry:
        return _load_raw(_make())

    def test_detect_exact_path_match(self) -> None:
        reg = self._reg()
        assert "alpha" in reg.detect_contexts(["services/alpha/"])

    def test_detect_prefix_match(self) -> None:
        reg = self._reg()
        assert "alpha" in reg.detect_contexts(["services/alpha/engine.py"])

    def test_detect_no_match(self) -> None:
        reg = self._reg()
        assert len(reg.detect_contexts(["services/unrelated/foo.py"])) == 0

    def test_detect_empty_files(self) -> None:
        reg = self._reg()
        assert reg.detect_contexts([]) == set()

    def test_detect_multiple_contexts(self) -> None:
        reg = self._reg()
        result = reg.detect_contexts(["services/alpha/a.py", "services/beta/b.py"])
        assert result == {"alpha", "beta"}

    def test_detect_irrelevant_file(self) -> None:
        reg = self._reg()
        assert reg.detect_contexts(["README.md"]) == set()

    def test_detect_returns_set(self) -> None:
        reg = self._reg()
        result = reg.detect_contexts(["services/alpha/x.py"])
        assert isinstance(result, set)

    def test_detect_path_not_prefix_of_sibling(self) -> None:
        reg = self._reg()
        # services/alpha_extra/ should NOT match services/alpha/
        result = reg.detect_contexts(["services/alpha_extra/foo.py"])
        assert "alpha" not in result


# ─────────────────────────────────────────────────────────────────────────────
# 6. Dependency Expansion
# ─────────────────────────────────────────────────────────────────────────────


class TestDependencyExpansion:
    def _reg(self) -> ContextRegistry:
        return _load_raw(_make())

    def test_expand_no_deps(self) -> None:
        reg = self._reg()
        result = reg.expand_dependencies({"alpha"})
        assert result == {"alpha"}

    def test_expand_direct_dep(self) -> None:
        reg = self._reg()
        result = reg.expand_dependencies({"beta"})
        assert "alpha" in result
        assert "beta" in result

    def test_expand_empty_input(self) -> None:
        reg = self._reg()
        assert reg.expand_dependencies(set()) == set()

    def test_expand_multiple_roots(self) -> None:
        reg = self._reg()
        result = reg.expand_dependencies({"alpha", "beta"})
        assert result == {"alpha", "beta"}

    def test_expand_transitive(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["gamma"] = {
            "description": "Gamma",
            "owners": [],
            "paths": ["services/gamma/"],
            "tests": ["tests/test_gamma.py"],
            "dependencies": ["beta"],
            "gates": {
                "authority": False,
                "contract": False,
                "privacy": False,
                "security": False,
            },
            "smoke": {"enabled": False},
        }
        reg = _load_raw(d)
        result = reg.expand_dependencies({"gamma"})
        assert result == {"gamma", "beta", "alpha"}

    def test_expand_deterministic(self) -> None:
        reg = self._reg()
        r1 = reg.expand_dependencies({"alpha", "beta"})
        r2 = reg.expand_dependencies({"beta", "alpha"})
        assert r1 == r2

    def test_expand_returns_set(self) -> None:
        reg = self._reg()
        result = reg.expand_dependencies({"alpha"})
        assert isinstance(result, set)

    def test_expand_unknown_context_ignored(self) -> None:
        reg = self._reg()
        result = reg.expand_dependencies({"alpha", "ghost"})
        assert "alpha" in result


# ─────────────────────────────────────────────────────────────────────────────
# 7. Test Collection
# ─────────────────────────────────────────────────────────────────────────────


class TestCollectTests:
    def _reg(self) -> ContextRegistry:
        return _load_raw(_make())

    def test_collect_own_tests(self) -> None:
        reg = self._reg()
        tests = reg.collect_tests({"alpha"})
        assert "tests/test_alpha.py" in tests

    def test_collect_includes_dep_tests(self) -> None:
        reg = self._reg()
        tests = reg.collect_tests({"beta"})
        # beta depends on alpha → alpha tests included
        assert "tests/test_alpha.py" in tests
        assert "tests/test_beta.py" in tests

    def test_collect_deduplication(self) -> None:
        reg = self._reg()
        tests = reg.collect_tests({"alpha", "beta"})
        assert tests.count("tests/test_alpha.py") == 1

    def test_collect_deterministic(self) -> None:
        reg = self._reg()
        t1 = reg.collect_tests({"alpha", "beta"})
        t2 = reg.collect_tests({"beta", "alpha"})
        assert t1 == t2

    def test_collect_empty_contexts(self) -> None:
        reg = self._reg()
        assert reg.collect_tests(set()) == []

    def test_collect_returns_list(self) -> None:
        reg = self._reg()
        result = reg.collect_tests({"alpha"})
        assert isinstance(result, list)

    def test_collect_order_alphabetical_by_context(self) -> None:
        reg = self._reg()
        tests = reg.collect_tests({"alpha", "beta"})
        # alpha < beta alphabetically → alpha test appears first
        assert tests.index("tests/test_alpha.py") < tests.index("tests/test_beta.py")

    def test_collect_node_id_tests_preserved(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["contexts"]["alpha"]["tests"] = ["tests/test_alpha.py::TestClass"]
        reg = _load_raw(d)
        tests = reg.collect_tests({"alpha"})
        assert "tests/test_alpha.py::TestClass" in tests


# ─────────────────────────────────────────────────────────────────────────────
# 8. Gate Collection
# ─────────────────────────────────────────────────────────────────────────────


class TestCollectGates:
    def _reg(self) -> ContextRegistry:
        return _load_raw(_make())

    def test_privacy_gate_fires_on_privacy_path(self) -> None:
        reg = self._reg()
        gates = reg.collect_gates(["services/cgin/privacy.py"])
        cmds = [" ".join(g) for g in gates]
        assert any("check_cgin_privacy" in c for c in cmds)

    def test_contract_gate_fires_on_api_path(self) -> None:
        reg = self._reg()
        gates = reg.collect_gates(["api/foo.py"])
        cmds = [" ".join(g) for g in gates]
        assert any("fg-contract" in c for c in cmds)

    def test_contract_gate_fires_on_services_path(self) -> None:
        reg = self._reg()
        gates = reg.collect_gates(["services/alpha/engine.py"])
        cmds = [" ".join(g) for g in gates]
        assert any("fg-contract" in c for c in cmds)

    def test_no_gate_on_unrelated_file(self) -> None:
        reg = self._reg()
        gates = reg.collect_gates(["README.md"])
        assert gates == []

    def test_empty_files_no_gates(self) -> None:
        reg = self._reg()
        assert reg.collect_gates([]) == []

    def test_gates_returns_list(self) -> None:
        reg = self._reg()
        result = reg.collect_gates(["api/foo.py"])
        assert isinstance(result, list)
        assert all(isinstance(g, list) for g in result)

    def test_privacy_and_contract_both_fire_on_authority_manifest(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["global"]["privacy_paths"].append("authority_manifest.yaml")
        d["global"]["contract_paths"].append("authority_manifest.yaml")
        reg = _load_raw(d)
        gates = reg.collect_gates(["authority_manifest.yaml"])
        assert len(gates) == 2

    def test_privacy_gate_on_check_cgin_privacy_file(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["global"]["privacy_paths"] = ["tools/ci/check_cgin_privacy.py"]
        reg = _load_raw(d)
        gates = reg.collect_gates(["tools/ci/check_cgin_privacy.py"])
        assert len(gates) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 9. Global Config
# ─────────────────────────────────────────────────────────────────────────────


class TestGlobalConfig:
    def test_always_tests_accessible(self) -> None:
        reg = _load_raw(_make())
        assert "tests/test_smoke.py" in reg.global_config.always_tests

    def test_always_gates_accessible(self) -> None:
        reg = _load_raw(_make())
        gates = reg.global_config.always_gates
        assert len(gates) >= 1
        assert isinstance(gates[0], tuple)

    def test_privacy_paths_accessible(self) -> None:
        reg = _load_raw(_make())
        assert "services/cgin/" in reg.global_config.privacy_paths

    def test_contract_paths_accessible(self) -> None:
        reg = _load_raw(_make())
        assert "api/" in reg.global_config.contract_paths

    def test_always_gates_non_list_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["global"]["always_gates"] = "string"
        with pytest.raises(
            RegistryValidationError, match="always_gates must be a list"
        ):
            _load_raw(d)

    def test_always_tests_non_list_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["global"]["always_tests"] = {"a": 1}
        with pytest.raises(RegistryValidationError, match="must be a list"):
            _load_raw(d)


# ─────────────────────────────────────────────────────────────────────────────
# 10. Digest and Serialisation
# ─────────────────────────────────────────────────────────────────────────────


class TestDigestAndSerialisation:
    def test_digest_is_sha256_hex(self) -> None:
        reg = _load_raw(_make())
        d = reg.digest()
        assert len(d) == 64
        assert all(c in "0123456789abcdef" for c in d)

    def test_digest_deterministic(self) -> None:
        reg1 = _load_raw(_make())
        reg2 = _load_raw(_make())
        assert reg1.digest() == reg2.digest()

    def test_digest_changes_on_different_registry(self) -> None:
        import copy

        d1 = _make()
        d2 = copy.deepcopy(d1)
        d2["version"] = 99
        reg1 = _load_raw(d1)
        reg2 = _load_raw(d2)
        assert reg1.digest() != reg2.digest()

    def test_real_registry_digest_stable(self) -> None:
        reg = ContextRegistry.load()
        d1 = reg.digest()
        d2 = reg.digest()
        assert d1 == d2


# ─────────────────────────────────────────────────────────────────────────────
# 11. Summary
# ─────────────────────────────────────────────────────────────────────────────


class TestSummary:
    def test_summarize_includes_version(self) -> None:
        reg = _load_raw(_make())
        s = reg.summarize()
        assert "v1" in s

    def test_summarize_includes_context_count(self) -> None:
        reg = _load_raw(_make())
        s = reg.summarize()
        assert "2" in s

    def test_summarize_includes_context_names(self) -> None:
        reg = _load_raw(_make())
        s = reg.summarize()
        assert "alpha" in s
        assert "beta" in s

    def test_summarize_returns_string(self) -> None:
        reg = _load_raw(_make())
        assert isinstance(reg.summarize(), str)


# ─────────────────────────────────────────────────────────────────────────────
# 12. Gate Commands Parsing
# ─────────────────────────────────────────────────────────────────────────────


class TestGateCommandsParsing:
    def test_privacy_command_stored(self) -> None:
        reg = _load_raw(_make())
        assert "check_cgin_privacy.py" in " ".join(reg.gate_commands.privacy)

    def test_contract_command_stored(self) -> None:
        reg = _load_raw(_make())
        assert "fg-contract" in " ".join(reg.gate_commands.contract)

    def test_empty_gate_command(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["gate_commands"]["privacy"] = []
        reg = _load_raw(d)
        # privacy gate with empty command should not fire
        gates = reg.collect_gates(["services/cgin/x.py"])
        cmds = [" ".join(g) for g in gates]
        assert not any("check_cgin_privacy" in c for c in cmds)

    def test_gate_commands_non_mapping_raises(self) -> None:
        import copy

        d = copy.deepcopy(_BASE)
        d["gate_commands"] = "invalid"
        with pytest.raises(RegistryValidationError, match="gate_commands"):
            _load_raw(d)


# ─────────────────────────────────────────────────────────────────────────────
# 13. Real Registry Integration
# ─────────────────────────────────────────────────────────────────────────────


class TestRealRegistry:
    def test_all_required_contexts_present(self) -> None:
        reg = ContextRegistry.load()
        required = {
            "cgin",
            "evidence_authority",
            "verification_authority",
            "evidence_freshness_authority",
            "freshness_score_history",
            "governance_chain",
            "governance_learning",
            "governance_adaptive_intelligence",
            "governance_optimization",
            "control_effectiveness",
            "remediation",
            "remediation_effectiveness",
        }
        assert required.issubset(set(reg.contexts.keys()))

    def test_cgin_has_no_deps(self) -> None:
        reg = ContextRegistry.load()
        assert reg.contexts["cgin"].dependencies == ()

    def test_governance_learning_depends_on_chain(self) -> None:
        reg = ContextRegistry.load()
        assert "governance_chain" in reg.contexts["governance_learning"].dependencies

    def test_governance_adaptive_depends_on_learning(self) -> None:
        reg = ContextRegistry.load()
        assert (
            "governance_learning"
            in reg.contexts["governance_adaptive_intelligence"].dependencies
        )

    def test_governance_optimization_expands_full_chain(self) -> None:
        reg = ContextRegistry.load()
        expanded = reg.expand_dependencies({"governance_optimization"})
        assert {
            "governance_optimization",
            "governance_adaptive_intelligence",
            "governance_learning",
            "governance_chain",
        }.issubset(expanded)

    def test_cgin_privacy_gate_true(self) -> None:
        reg = ContextRegistry.load()
        assert reg.contexts["cgin"].gates["privacy"] is True

    def test_cgin_contract_gate_false(self) -> None:
        reg = ContextRegistry.load()
        assert reg.contexts["cgin"].gates["contract"] is False

    def test_authority_contexts_have_contract_true(self) -> None:
        reg = ContextRegistry.load()
        for name in (
            "governance_chain",
            "governance_learning",
            "remediation_effectiveness",
        ):
            assert reg.contexts[name].gates["contract"] is True, name

    def test_all_contexts_have_non_empty_owners(self) -> None:
        reg = ContextRegistry.load()
        for name, ctx in reg.contexts.items():
            assert len(ctx.owners) > 0, f"context '{name}' has no owners"

    def test_always_gates_has_authority_integration(self) -> None:
        reg = ContextRegistry.load()
        flat = [" ".join(g) for g in reg.global_config.always_gates]
        assert any("check_authority_integration" in g for g in flat)

    def test_always_tests_non_empty(self) -> None:
        reg = ContextRegistry.load()
        assert len(reg.global_config.always_tests) > 0

    def test_privacy_paths_include_cgin(self) -> None:
        reg = ContextRegistry.load()
        assert "services/cgin/" in reg.global_config.privacy_paths

    def test_contract_paths_include_api(self) -> None:
        reg = ContextRegistry.load()
        assert "api/" in reg.global_config.contract_paths

    def test_detect_cgin_from_privacy_file(self) -> None:
        reg = ContextRegistry.load()
        ctxs = reg.detect_contexts(["services/cgin/privacy.py"])
        assert "cgin" in ctxs

    def test_detect_governance_learning_from_engine(self) -> None:
        reg = ContextRegistry.load()
        ctxs = reg.detect_contexts(["services/governance_learning/engine.py"])
        assert "governance_learning" in ctxs

    def test_detect_optimization_from_api(self) -> None:
        reg = ContextRegistry.load()
        ctxs = reg.detect_contexts(["api/governance_optimization.py"])
        assert "governance_optimization" in ctxs

    def test_collect_remediation_effectiveness_includes_learning_tests(self) -> None:
        reg = ContextRegistry.load()
        tests = reg.collect_tests({"remediation_effectiveness"})
        assert any("governance_learning" in t for t in tests)

    def test_collect_verification_includes_cgin_tests(self) -> None:
        reg = ContextRegistry.load()
        tests = reg.collect_tests({"verification_authority"})
        assert "tests/test_cgin_privacy.py" in tests

    def test_no_circular_deps_in_real_registry(self) -> None:
        # Would raise during load if circular deps existed
        reg = ContextRegistry.load()
        assert reg is not None

    def test_no_duplicate_paths_in_real_registry(self) -> None:
        reg = ContextRegistry.load()
        all_paths: list[str] = []
        for ctx in reg.contexts.values():
            all_paths.extend(ctx.paths)
        assert len(all_paths) == len(set(all_paths))

    def test_no_duplicate_tests_in_real_registry(self) -> None:
        reg = ContextRegistry.load()
        all_tests: list[str] = []
        for ctx in reg.contexts.values():
            all_tests.extend(ctx.tests)
        assert len(all_tests) == len(set(all_tests))

    def test_privacy_gate_fires_on_authority_manifest(self) -> None:
        reg = ContextRegistry.load()
        gates = reg.collect_gates(["authority_manifest.yaml"])
        cmds = [" ".join(g) for g in gates]
        assert any("check_cgin_privacy" in c for c in cmds)

    def test_contract_gate_fires_on_authority_manifest(self) -> None:
        reg = ContextRegistry.load()
        gates = reg.collect_gates(["authority_manifest.yaml"])
        cmds = [" ".join(g) for g in gates]
        assert any("fg-contract" in c for c in cmds)
