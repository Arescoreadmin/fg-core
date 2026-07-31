"""Manifest signing tests (HMAC-SHA256).

The signing helper lives in `scripts/backup/fg_backup.sh` (`sign_manifest` and
`verify_manifest_impl`). These tests drive it end-to-end via the CLI so the
in-shell wiring stays honest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "backup" / "fg_backup.sh"


def _bash_sign(manifest_path: Path, key: str | None) -> None:
    """Invoke sign_manifest from the shell script against manifest_path."""
    # Sourcing fg_backup.sh with no argv triggers main() -> print_help (exit 0),
    # which is a no-op for our purposes. After sourcing, sign_manifest is in
    # scope and we can call it directly.
    script_body = (
        f'source "{SCRIPT}" >/dev/null 2>&1 || true; sign_manifest "{manifest_path}"'
    )
    env = {"PATH": "/usr/bin:/bin"}
    if key is not None:
        env["FG_BACKUP_MANIFEST_HMAC_KEY"] = key
    subprocess.run(
        ["bash", "-c", script_body],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def _bash_verify(manifest_path: Path, key: str | None) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin"}
    if key is not None:
        env["FG_BACKUP_MANIFEST_HMAC_KEY"] = key
    return subprocess.run(
        ["bash", str(SCRIPT), "verify-manifest", str(manifest_path)],
        capture_output=True,
        text=True,
        env=env,
    )


def test_manifest_with_hmac_key_produces_non_unsigned_signature(seed_backup):
    _archive, manifest = seed_backup()
    _bash_sign(manifest, "correct-horse-battery-staple")
    doc = json.loads(manifest.read_text())
    assert doc["manifest_signature"].startswith("sha256-hmac:")
    assert doc["manifest_signing_key_id"] == "env:FG_BACKUP_MANIFEST_HMAC_KEY"


def test_manifest_without_hmac_key_produces_unsigned_signature(seed_backup):
    _archive, manifest = seed_backup()
    _bash_sign(manifest, None)
    doc = json.loads(manifest.read_text())
    assert doc["manifest_signature"] == "unsigned"
    assert doc["manifest_signing_key_id"] == "none"


def test_verify_manifest_with_correct_key_returns_match(seed_backup):
    _archive, manifest = seed_backup()
    _bash_sign(manifest, "the-key")
    result = _bash_verify(manifest, "the-key")
    assert result.returncode == 0
    assert "PASS manifest_signature" in result.stdout


def test_verify_manifest_with_wrong_key_returns_mismatch(seed_backup):
    _archive, manifest = seed_backup()
    _bash_sign(manifest, "signing-key")
    result = _bash_verify(manifest, "different-key")
    assert result.returncode == 1
    assert "FAIL manifest_signature" in result.stdout


def test_verify_manifest_on_unsigned_manifest_exits_zero(seed_backup):
    _archive, manifest = seed_backup()
    # Explicitly leave signature as "unsigned" (that's what the seed sets).
    result = _bash_verify(manifest, None)
    assert result.returncode == 0
    assert "UNSIGNED" in result.stdout


def test_signature_is_computed_over_stripped_manifest(seed_backup):
    """Signature must exclude the signature fields themselves so verify is stable."""
    _archive, manifest = seed_backup()
    key = "predictable"
    _bash_sign(manifest, key)
    doc = json.loads(manifest.read_text())
    # Recompute the expected HMAC by stripping the signature fields.
    copy = dict(doc)
    for f in ("manifest_signature", "manifest_signing_key_id", "manifest_verify_cmd"):
        copy.pop(f, None)
    canonical = json.dumps(copy, indent=2, sort_keys=True) + "\n"
    expected = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    assert doc["manifest_signature"] == f"sha256-hmac:{expected}"
