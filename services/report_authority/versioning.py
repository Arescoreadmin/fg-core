"""services/report_authority/versioning.py — Report version management utilities.

ReportVersion is an immutable dataclass representing a semantic version with
assessment and report revision counters.

Version string format: "MAJOR.MINOR.PATCH-rREPORT_REVISION"
  e.g. "1.0.0-r0", "1.0.1-r3"

Assessment revision is tracked separately and is not included in the string
representation — it is stored in the database for lineage tracing.
"""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class ReportVersion:
    """Immutable semantic version with report and assessment revision counters."""

    major: int
    minor: int
    patch: int
    assessment_revision: int = 0
    report_revision: int = 0

    def __str__(self) -> str:
        """Return the canonical string form: 'MAJOR.MINOR.PATCH-rREPORT_REVISION'."""
        return f"{self.major}.{self.minor}.{self.patch}-r{self.report_revision}"

    def bump_report_revision(self) -> ReportVersion:
        """Return a new ReportVersion with report_revision incremented by 1."""
        return replace(self, report_revision=self.report_revision + 1)

    def bump_patch(self) -> ReportVersion:
        """Return a new ReportVersion with patch incremented and report_revision reset."""
        return replace(self, patch=self.patch + 1, report_revision=0)


def parse_version(version_str: str) -> ReportVersion:
    """Parse a version string of the form 'MAJOR.MINOR.PATCH-rREPORT_REVISION'.

    Raises ValueError if the string is not in the expected format.
    """
    try:
        core, revision_part = version_str.split("-r", maxsplit=1)
        major_str, minor_str, patch_str = core.split(".", maxsplit=2)
        return ReportVersion(
            major=int(major_str),
            minor=int(minor_str),
            patch=int(patch_str),
            report_revision=int(revision_part),
        )
    except (ValueError, AttributeError) as exc:
        raise ValueError(
            f"Invalid version string: {version_str!r}. "
            "Expected format: 'MAJOR.MINOR.PATCH-rREPORT_REVISION' (e.g. '1.0.0-r0')."
        ) from exc


def compare_versions(a: ReportVersion, b: ReportVersion) -> int:
    """Compare two ReportVersion instances.

    Returns:
        -1 if a < b
         0 if a == b
         1 if a > b

    Comparison is lexicographic over (major, minor, patch, report_revision).
    assessment_revision is intentionally excluded from ordering.
    """
    a_key = (a.major, a.minor, a.patch, a.report_revision)
    b_key = (b.major, b.minor, b.patch, b.report_revision)
    if a_key < b_key:
        return -1
    if a_key > b_key:
        return 1
    return 0
