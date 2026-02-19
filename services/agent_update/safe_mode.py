from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UpdateSafeMode:
    failure_threshold: int = 3
    last_manifest_version: str = ""
    consecutive_failures: int = 0
    blocked_until_new_manifest: bool = False

    def can_attempt(self, manifest_version: str) -> bool:
        if not self.blocked_until_new_manifest:
            return True
        return manifest_version != self.last_manifest_version

    def record_failure(self, manifest_version: str) -> None:
        if manifest_version != self.last_manifest_version:
            self.last_manifest_version = manifest_version
            self.consecutive_failures = 0
            self.blocked_until_new_manifest = False
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold:
            self.blocked_until_new_manifest = True

    def record_success(self, manifest_version: str) -> None:
        self.last_manifest_version = manifest_version
        self.consecutive_failures = 0
        self.blocked_until_new_manifest = False
