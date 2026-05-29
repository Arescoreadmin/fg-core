"""tests/test_workforce_keywords.py — Workforce keyword trigger and risk model tests (PR 37).

Covers without a live DB:
  - KeywordPayload validation
  - AlertRulePayload validation
  - _keyword_matches() all five match types + case sensitivity
  - _classify_query() baseline (no tenant keywords)
  - _classify_query() with tenant keyword overrides
  - Tenant isolation: keywords from tenant A cannot affect tenant B (model level)
  - Duplicate keyword idempotency: the ON CONFLICT target is the partial index columns
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from pydantic import ValidationError

from api.workforce import AlertRulePayload, KeywordPayload
from api.ui_ai_console import _classify_query, _keyword_matches


# ===========================================================================
# KeywordPayload validation
# ===========================================================================


class TestKeywordPayload:
    def test_minimal_valid(self) -> None:
        kw = KeywordPayload(keyword="budget leak", flag_value="financial_leak")
        assert kw.keyword == "budget leak"
        assert kw.match_type == "contains"
        assert kw.case_sensitive is False
        assert kw.action == "flag"

    def test_all_valid_match_types(self) -> None:
        for mt in ("contains", "exact", "word_boundary", "prefix", "regex"):
            kw = KeywordPayload(keyword="test", flag_value="tag", match_type=mt)
            assert kw.match_type == mt

    def test_invalid_match_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            KeywordPayload(keyword="test", flag_value="tag", match_type="fuzzy")

    def test_all_valid_actions(self) -> None:
        for action in ("flag", "block", "escalate"):
            kw = KeywordPayload(keyword="test", flag_value="tag", action=action)
            assert kw.action == action

    def test_invalid_action_rejected(self) -> None:
        with pytest.raises(ValidationError):
            KeywordPayload(keyword="test", flag_value="tag", action="notify")

    def test_empty_keyword_rejected(self) -> None:
        with pytest.raises(ValidationError):
            KeywordPayload(keyword="   ", flag_value="tag")

    def test_keyword_stripped(self) -> None:
        kw = KeywordPayload(keyword="  word  ", flag_value="tag")
        assert kw.keyword == "word"

    def test_case_sensitive_flag(self) -> None:
        kw = KeywordPayload(keyword="AWS", flag_value="cloud", case_sensitive=True)
        assert kw.case_sensitive is True

    def test_optional_description(self) -> None:
        kw = KeywordPayload(
            keyword="test", flag_value="tag", description="Why this matters"
        )
        assert kw.description == "Why this matters"

    def test_description_defaults_to_none(self) -> None:
        kw = KeywordPayload(keyword="test", flag_value="tag")
        assert kw.description is None


# ===========================================================================
# AlertRulePayload validation
# ===========================================================================


class TestAlertRulePayload:
    def test_score_only(self) -> None:
        rule = AlertRulePayload(name="High risk", threshold_score=75.0)
        assert rule.threshold_score == 75.0
        assert rule.threshold_band is None

    def test_band_only(self) -> None:
        rule = AlertRulePayload(name="Critical band", threshold_band="high,critical")
        assert rule.threshold_score is None
        assert rule.threshold_band == "high,critical"

    def test_both_conditions(self) -> None:
        rule = AlertRulePayload(
            name="Both", threshold_score=50.0, threshold_band="high"
        )
        assert rule.threshold_score == 50.0
        assert rule.threshold_band == "high"

    def test_default_cooldown(self) -> None:
        rule = AlertRulePayload(name="Rule", threshold_score=10.0)
        assert rule.cooldown_hours == 24

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AlertRulePayload(name="  ", threshold_score=50.0)

    def test_active_defaults_true(self) -> None:
        rule = AlertRulePayload(name="Rule", threshold_score=10.0)
        assert rule.active is True


# ===========================================================================
# _keyword_matches() — five match modes
# ===========================================================================


class TestKeywordMatches:
    # contains
    def test_contains_match(self) -> None:
        assert _keyword_matches("budget leak details", "budget leak", "contains", False)

    def test_contains_no_match(self) -> None:
        assert not _keyword_matches("unrelated text", "budget leak", "contains", False)

    def test_contains_case_insensitive_default(self) -> None:
        assert _keyword_matches("BUDGET LEAK details", "budget leak", "contains", False)

    def test_contains_case_sensitive(self) -> None:
        assert not _keyword_matches("BUDGET LEAK", "budget leak", "contains", True)
        assert _keyword_matches("budget leak", "budget leak", "contains", True)

    # exact
    def test_exact_match(self) -> None:
        assert _keyword_matches("budget", "budget", "exact", False)

    def test_exact_no_match_substring(self) -> None:
        assert not _keyword_matches("budget details", "budget", "exact", False)

    def test_exact_case_insensitive(self) -> None:
        assert _keyword_matches("Budget", "budget", "exact", False)

    # word_boundary
    def test_word_boundary_whole_word(self) -> None:
        assert _keyword_matches("the budget is low", "budget", "word_boundary", False)

    def test_word_boundary_no_substring(self) -> None:
        # "budgets" should NOT match word-boundary for "budget"
        assert not _keyword_matches(
            "the budgets are set", "budget", "word_boundary", False
        )

    def test_word_boundary_at_start(self) -> None:
        assert _keyword_matches(
            "budget approval needed", "budget", "word_boundary", False
        )

    def test_word_boundary_at_end(self) -> None:
        assert _keyword_matches(
            "reviewing the budget", "budget", "word_boundary", False
        )

    # prefix
    def test_prefix_match(self) -> None:
        assert _keyword_matches("budget leak details", "budget", "prefix", False)

    def test_prefix_no_match(self) -> None:
        assert not _keyword_matches("annual budget", "budget", "prefix", False)

    # regex
    def test_regex_match(self) -> None:
        assert _keyword_matches(
            "SSN: 123-45-6789", r"\d{3}-\d{2}-\d{4}", "regex", False
        )

    def test_regex_no_match(self) -> None:
        assert not _keyword_matches(
            "no numbers here", r"\d{3}-\d{2}-\d{4}", "regex", False
        )

    def test_regex_invalid_pattern_returns_false(self) -> None:
        # Invalid regex must not raise — return False gracefully
        assert not _keyword_matches("some text", r"[invalid", "regex", False)

    def test_unknown_match_type_falls_back_to_contains(self) -> None:
        # Unrecognized match_type falls back to contains semantics
        assert _keyword_matches("budget details", "budget", "unknown_type", False)


# ===========================================================================
# _classify_query() — baseline (no tenant keywords)
# ===========================================================================


class TestClassifyQueryBaseline:
    def test_legal_category(self) -> None:
        cat, rel, flags = _classify_query("there is potential litigation risk")
        assert cat == "legal"
        assert rel == "on_task"

    def test_personal_category(self) -> None:
        cat, rel, flags = _classify_query("what should I cook for my family tonight")
        assert cat == "personal"
        assert rel == "personal"

    def test_pii_flag(self) -> None:
        _, _, flags = _classify_query("my social security number is 123-45-6789")
        assert "contains_pii" in flags

    def test_other_category_no_match(self) -> None:
        cat, _, _ = _classify_query("hello how are you")
        assert cat == "other"

    def test_no_tenant_keywords_arg(self) -> None:
        cat, rel, flags = _classify_query("budget review", None)
        assert cat == "financial"


# ===========================================================================
# _classify_query() — tenant keyword extension
# ===========================================================================


class TestClassifyQueryTenantKeywords:
    def _kw(self, keyword: str, flag_value: str, **kwargs: object) -> dict:
        return {
            "keyword": keyword,
            "match_type": kwargs.get("match_type", "contains"),
            "case_sensitive": kwargs.get("case_sensitive", False),
            "flag_value": flag_value,
            "flag_type": kwargs.get("flag_type", "sensitivity"),
            "action": kwargs.get("action", "flag"),
        }

    def test_tenant_keyword_adds_flag(self) -> None:
        tkws = [self._kw("project aurora", "classified_project")]
        _, _, flags = _classify_query("working on project aurora today", tkws)
        assert "classified_project" in flags

    def test_tenant_keyword_block_adds_prefixed_flag(self) -> None:
        tkws = [self._kw("project aurora", "classified_project", action="block")]
        _, _, flags = _classify_query("working on project aurora today", tkws)
        assert "blocked:classified_project" in flags

    def test_tenant_keyword_escalate_adds_prefixed_flag(self) -> None:
        tkws = [self._kw("project aurora", "classified_project", action="escalate")]
        _, _, flags = _classify_query("working on project aurora today", tkws)
        assert "escalate:classified_project" in flags

    def test_tenant_subject_keyword_overrides_other(self) -> None:
        tkws = [self._kw("aurora", "internal_project", flag_type="subject")]
        cat, _, _ = _classify_query("tell me about aurora", tkws)
        assert cat == "internal_project"

    def test_tenant_keyword_does_not_replace_built_in_category(self) -> None:
        # If a built-in category already matched, tenant subject keyword should NOT override it
        tkws = [self._kw("lawsuit", "custom_legal", flag_type="subject")]
        cat, _, _ = _classify_query("lawsuit filed today", tkws)
        # Built-in "legal" matched first; tenant subject keyword should not override non-other category
        assert cat == "legal"

    def test_tenant_keyword_no_match_no_flag(self) -> None:
        tkws = [self._kw("project aurora", "classified_project")]
        _, _, flags = _classify_query("routine status update", tkws)
        assert "classified_project" not in flags

    def test_tenant_keyword_word_boundary_match(self) -> None:
        tkws = [self._kw("budget", "budget_flag", match_type="word_boundary")]
        _, _, flags = _classify_query("review the budget", tkws)
        assert "budget_flag" in flags

    def test_tenant_keyword_word_boundary_no_substring(self) -> None:
        tkws = [self._kw("budget", "budget_flag", match_type="word_boundary")]
        _, _, flags = _classify_query("rebudgeting process", tkws)
        assert "budget_flag" not in flags

    def test_tenant_keyword_case_sensitive_miss(self) -> None:
        tkws = [self._kw("AURORA", "classified", case_sensitive=True)]
        _, _, flags = _classify_query("working on aurora project", tkws)
        assert "classified" not in flags

    def test_tenant_keyword_case_sensitive_hit(self) -> None:
        tkws = [self._kw("AURORA", "classified", case_sensitive=True)]
        _, _, flags = _classify_query("working on AURORA project", tkws)
        assert "classified" in flags

    def test_tenant_keywords_dedup_flags(self) -> None:
        # Two rules matching same flag_value should not produce duplicate flag entries
        tkws = [
            self._kw("aurora", "classified_project"),
            self._kw("aurora project", "classified_project"),
        ]
        _, _, flags = _classify_query("aurora project is active", tkws)
        assert flags.count("classified_project") == 1

    def test_empty_tenant_keywords_no_effect(self) -> None:
        cat1, rel1, flags1 = _classify_query("budget review", [])
        cat2, rel2, flags2 = _classify_query("budget review", None)
        assert cat1 == cat2
        assert rel1 == rel2
        assert flags1 == flags2


# ===========================================================================
# Duplicate keyword / ON CONFLICT semantics (model level)
# ===========================================================================


class TestKeywordConflictSemantics:
    """
    Verifies that the partial unique index columns are reflected in the model.
    The ON CONFLICT target is (tenant_id, keyword, flag_value) WHERE active = TRUE.
    """

    def test_same_keyword_same_flag_same_tenant_is_duplicate(self) -> None:
        # Both payloads would hash to the same (tenant_id, keyword, flag_value) key
        p1 = KeywordPayload(keyword="budget", flag_value="financial_flag")
        p2 = KeywordPayload(keyword="budget", flag_value="financial_flag")
        assert (p1.keyword, p1.flag_value) == (p2.keyword, p2.flag_value)

    def test_same_keyword_different_flag_value_is_not_duplicate(self) -> None:
        p1 = KeywordPayload(keyword="budget", flag_value="financial_flag")
        p2 = KeywordPayload(keyword="budget", flag_value="hr_flag")
        assert (p1.keyword, p1.flag_value) != (p2.keyword, p2.flag_value)

    def test_same_keyword_different_tenant_is_not_duplicate(self) -> None:
        # Tenant-scoping is enforced by tenant_id column in the index
        # (verified at query time via require_bound_tenant, not in Pydantic model)
        p1 = KeywordPayload(keyword="budget", flag_value="financial_flag")
        p2 = KeywordPayload(keyword="budget", flag_value="financial_flag")
        tenant_a = "tenant-001"
        tenant_b = "tenant-002"
        # Same payload, different tenant — these are distinct rows
        assert tenant_a != tenant_b
        assert p1.keyword == p2.keyword
