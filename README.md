## Local dev: API keys
- Create `secrets/fg_api_keys.txt` (not committed) using the format shown in:
  - `secrets/fg_api_keys.example.txt`

<!-- toc -->



<!-- tocstop -->



# fg-core

Authoritative requirements live in `BLUEPRINT_STAGED.md`.
Note: we hard-block `ecdsa` due to a CVE with no fix versions; do not add `python-jose`.

## Dashboards & audit packet export
- Tenant dashboards (UI): `/ui/dash/posture`, `/ui/dash/forensics`, `/ui/dash/controls`
- Admin console (UI): `/admin/dashboard`
- Evidence export API: `POST /ui/audit/packet` returns a download URL for a deterministic bundle
  containing `decisions.jsonl`, `chain_verification.json`, and `manifest.json` (plus `sbom.json`
  and `provenance.json` when present).
- Audit packet export is experimental until MVP-3 verification APIs are complete.
