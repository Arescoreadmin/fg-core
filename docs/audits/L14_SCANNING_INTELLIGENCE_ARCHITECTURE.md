# L14 Scanning Intelligence Architecture — Future Recommendations

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

Three to five concrete architectural recommendations to advance FrostGate's scanning intelligence, with rationale and competitive moat analysis.

---

## Recommendation 1: Cross-Scanner AI Governance Correlation Graph

**Current state:** The 4-layer AI governance chain (tool discovery → data access mapping → risk register → governance engine) produces per-tool records with cross-reference IDs (graph_node_id, vendor_node_id, decision_node_id, etc.). These IDs exist but the traversal layer is not built. Each scanner produces evidence in isolation.

**Recommendation:** Build a lightweight evidence graph traversal API that connects:
- `ai_tool:{tenant_id}:{app_id}` (from tool discovery)
- `risk:{tenant_id}:{record_id}` (from risk register)
- `governance:{tenant_id}:{record_id}` (from governance engine)
- `entra_user:{tenant_id}:{principal_id}` (from entra_governance assigned_users)
- `device:{tenant_id}:{device_id}` (from endpoint_inventory)

This enables cross-scanner queries like: "Show me all users with Global Admin AND with an active AI tool that has no DPA AND whose device is unencrypted." This is the kind of multi-domain risk correlation that justifies an enterprise security assessment platform over individual point tools.

**Implementation path:** Extend `services/governance_graph/builder.py` (already partially built) to ingest scan results from all connectors, not just the governance chain. Expose a `GET /engagements/{id}/risk-graph/correlation` endpoint.

**Competitive moat:** No compliance scanner today provides cross-domain evidence correlation that links identity posture to AI governance posture to device posture. This would be a distinctive FrostGate capability.

---

## Recommendation 2: Longitudinal Drift Detection for AI Governance

**Current state:** The drift engine (`services/connectors/drift/`) monitors configuration changes over time. It is not wired to the AI governance chain.

**Recommendation:** Extend drift detection to monitor AI governance state changes longitudinally:
- Shadow AI tools appearing between assessments (new unreviewed service principals)
- Risk acceptance expiring since last scan
- Governance records degrading (complete → partial → unknown) due to owner departure
- New admin-consented OAuth grants since the previous scan

The drift engine already has alerts, correlation, velocity, and scoring modules. The gap is that it does not receive AI governance scan results as input.

**Implementation path:** Add an `ai_governance` drift source type to `services/connectors/drift/engine.py`. Connect the ai_vendor_governance bridge to emit drift events when governance records change state.

**Value:** Enables FrostGate to offer continuous monitoring subscriptions after the initial assessment — a recurring revenue model that point-in-time scanners cannot provide.

---

## Recommendation 3: Cryptographic Payload Integrity for All Scanners

**Current state:** Only the Microsoft Graph connector has a full manifest signing chain (`services/connectors/msgraph/integrity.py`). All other scanners produce `scan_id` UUIDs but no tamper-evident signature over the raw payload.

**Recommendation:** Implement a lightweight signing step in the FA layer that computes `SHA-256(raw_payload_json)` and stores it as `payload_hash` in the `FaScanResult` row. This is a minimal evidence defensibility improvement that does not require Vault Transit or PKI.

For regulated clients (HIPAA, FedRAMP, CMMC), offer Vault Transit signing of the hash. The architecture already exists in the Microsoft Graph connector — generalize it.

**Implementation path:**
1. Add `payload_hash` column to `fa_scan_results`
2. Compute `SHA-256` of the raw payload JSON in `_create_scan_result()` in `services/field_assessment/store.py`
3. Optionally sign the hash via Vault Transit for clients with EVIDENCE_SIGNING_ENABLED

**Value:** Raises all non-Graph scanners from evidence defensibility score 3 to 4+. Required for clients that will challenge evidence in litigation or regulatory proceedings.

---

## Recommendation 4: AI Model Server and Shadow Infrastructure Discovery

**Current state:** The network scanner probes for AI model server ports (11434 Ollama, 7860 Gradio, 8888 Jupyter, 6006 TensorBoard) but only on operator-specified hosts. It does not discover new hosts that may be running AI servers on the internal network.

**Recommendation:** Add an optional asset discovery pre-scan that:
1. Accepts a network CIDR from the operator (pre-authorized)
2. Probes for AI-specific ports only (not a full port scan) on hosts in the CIDR
3. Returns a list of discovered AI-serving hosts for operator review before full scanning

This is the network-layer equivalent of AI tool discovery — finding shadow AI infrastructure before the assessor knows to look for it.

**Safety boundary:** This recommendation requires SSRF controls and operator pre-authorization. It MUST NOT be automated or triggered without explicit operator approval and written client authorization. The validator already supports CIDR inputs.

**Implementation path:** Extend `run_network_scan` with an optional `discovery_mode=True` that uses only `_AI_PORTS` and returns candidate hosts for review.

**Value:** Closes the browser/API-based shadow AI detection gap by finding AI infrastructure rather than AI app registrations.

---

## Recommendation 5: Assessment-to-Assessment Benchmarking

**Current state:** Each assessment is a point-in-time snapshot. There is no mechanism to compare a client's scores against industry benchmarks or against their own previous assessments.

**Recommendation:** Build a benchmarking layer that:
1. Anonymizes and aggregates finding distributions across all engagements (tenant-isolated; raw data never crosses tenants)
2. Provides a percentile position for each domain score (e.g., "your MFA coverage is in the 42nd percentile for healthcare organizations")
3. Computes improvement velocity for repeat clients

**Implementation path:** Add an aggregation query to `services/field_assessment/store.py` that produces anonymized score distributions. Store anonymized benchmark snapshots in a separate table with no tenant_id linkage.

**Competitive moat:** Benchmarking data is a network-effect moat. No point-in-time scanner has it at engagement 1. FrostGate gains it progressively as the assessment volume grows. After 50 engagements, the benchmark data becomes a defensible differentiator in enterprise sales.

**Privacy boundary:** Benchmark aggregation must be explicitly opt-in per client. Raw finding details never leave the tenant's evidence partition.
