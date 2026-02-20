#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "== git status =="
git status -sb

echo
echo "== 1) Find duplicate migration versions =="
python - <<'PY'
from pathlib import Path
mig_dir = Path("migrations/postgres")
versions = {}
dupes = []
for p in sorted(mig_dir.glob("*.sql")):
    if p.name.endswith(".rollback.sql"):
        continue
    ver = p.name.split("_", 1)[0]
    versions.setdefault(ver, []).append(p.name)

for ver, names in versions.items():
    if len(names) > 1:
        dupes.append((ver, names))

if not dupes:
    print("OK: no dupes")
else:
    print("DUPLICATES FOUND:")
    for ver, names in dupes:
        print(f"  {ver}:")
        for n in names:
            print(f"    - {n}")
PY

echo
echo "== 2) Show whether agent routes exist in app =="
python - <<'PY'
from api.main import build_app
app = build_app()
want_prefixes = ("/agent/", "/admin/agent/")
hits = []
for r in app.routes:
    path = getattr(r, "path", "")
    if any(path.startswith(p) for p in want_prefixes):
        methods = ",".join(sorted(getattr(r, "methods", []) or []))
        hits.append((path, methods))
print("agent/admin-agent routes:", len(hits))
for p,m in sorted(hits):
    print(f"{m:10} {p}")
PY

echo
echo "== 3) Locate where agent routers should be included =="
rg -n "agent" api/main.py api/main.* api/*.py || true

echo
echo "== 4) OpenAPI ingest schema ref mismatch =="
python - <<'PY'
import json
from pathlib import Path
spec = json.loads(Path("contracts/core/openapi.json").read_text(encoding="utf-8"))
ref = spec["paths"]["/ingest"]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"]
print("openapi /ingest $ref:", ref)
PY

echo
echo "== 5) Quick failing-test repro list =="
pytest -q \
  tests/test_billing_module.py::test_evidence_export_contains_manifest_and_attestation \
  tests/agent/test_phase2_enterprise.py::test_quarantine_restricts_commands \
  tests/test_openapi_ingest_event_id_required.py::test_openapi_ingest_requires_event_id \
  tests/security/test_spine_enforcement.py::test_auth_context_stamped_only_when_authenticated \
  tests/test_audit_search.py::test_audit_pagination_is_stable \
  -q || true