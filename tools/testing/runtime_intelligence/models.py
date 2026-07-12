"""Frozen dataclasses for the runtime intelligence package."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SlowTest:
    node_id: str
    duration_seconds: float
    phase: str  # "call" | "setup" | "teardown" | "collection"


@dataclass(frozen=True)
class SlowFixture:
    name: str
    duration_seconds: float


@dataclass(frozen=True)
class RuntimeMetadata:
    schema_version: str  # "1.0"
    gate: str  # "fg-fast" | "fg-security" | "fg-contract" | "fg-full"
    commit_sha: str
    workflow: str
    job: str
    runner_os: str
    python_version: str
    started_at: str  # ISO 8601
    completed_at: str  # ISO 8601
    duration_seconds: float
    environment_fingerprint: str
    dependency_fingerprint: str


@dataclass(frozen=True)
class RuntimeResult:
    meta: RuntimeMetadata
    collected: int
    passed: int
    failed: int
    skipped: int
    xfailed: int
    warnings: int
    duration_seconds: float
    slowest_tests: tuple[SlowTest, ...]  # top 25, sorted desc by duration
    slowest_fixtures: tuple[SlowFixture, ...]  # top 25


@dataclass(frozen=True)
class RollingStats:
    count: int
    mean: float
    median: float
    p90: float
    p95: float
    minimum: float
    maximum: float
    std_dev: float


@dataclass(frozen=True)
class Regression:
    gate: str
    field: str  # "duration_seconds" | "collection" | "slowest_fixture"
    current_value: float
    baseline_value: float
    pct_change: float
    severity: str  # "low" | "medium" | "high" | "critical"
    message: str
