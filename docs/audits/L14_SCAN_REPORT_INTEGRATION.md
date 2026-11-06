# L14 Scanner-to-Report Path Analysis

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

For each connector, traces the path from scan execution through evidence record creation to finding generation to report section inclusion. Identifies stranded outputs.

---

## Integration Architecture Overview

```
Scan Runner
    │
    ▼
FaScanResult (raw payload stored)
    │
    ├──► _auto_link_scan_evidence() → FaEvidenceLink (engagement-level)
    │
    ├──► Connector bridge (services/field_assessment/connectors/*_bridge.py)
    │       │
    │       ├──► Findings extracted → FaNormalizedFinding rows
    │       │
    │       └──► Source-type-specific records (FaMsgraphScanReport, FaAiVendorGovernanceRecord, etc.)
    │
    └──► Evidence lifecycle (H15) — collected → locked → legal_hold
```

---

## microsoft_graph

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/msgraph/runner.py::run_scan() | Implemented |
| Raw collection | 8 analyzers: mfa, conditional_access, enterprise_apps, guest_exposure, privileged_roles, oauth_consent, ai_signals, dlp_scoring | Implemented |
| Evidence normalization | services/field_assessment/connectors/msgraph_bridge.py | Implemented |
| Evidence record | FaScanResult + FaMsgraphScanReport + FaMsgraphManifest | Implemented |
| Finding linkage | Findings extracted from ScanResult.findings by bridge | Implemented |
| Report inclusion | Yes — msgraph findings appear in engagement report via FaNormalizedFinding query | Implemented |
| Stranded output | None identified |

---

## entra_governance

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/entra_governance/runner.py::run_entra_governance() | Implemented |
| Evidence record | FaScanResult with source_type=entra_governance | Implemented |
| Finding linkage | services/field_assessment/connectors/entra_governance_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Stranded output | None identified |

---

## endpoint_inventory

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/endpoint_inventory/runner.py::run_endpoint_inventory() | Implemented |
| Evidence record | FaScanResult with source_type=endpoint_inventory | Implemented |
| Finding linkage | services/field_assessment/connectors/endpoint_inventory_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Stranded output | None identified |

---

## oauth_inventory

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/oauth_inventory/runner.py::run_oauth_inventory() | Implemented |
| Evidence record | FaScanResult with source_type=oauth_inventory | Implemented |
| Finding linkage | services/field_assessment/connectors/oauth_inventory_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Stranded output | None identified |

---

## oauth_risk

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/oauth_risk/runner.py | Implemented |
| Evidence record | FaScanResult with source_type=oauth_risk | Implemented |
| Finding linkage | services/field_assessment/connectors/oauth_risk_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Stranded output | None identified |

---

## ai_tool_discovery (PR1)

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/ai_tool_discovery/runner.py::run_ai_tool_discovery() | Implemented |
| Evidence record | FaScanResult with source_type=ai_tool_discovery | Implemented |
| Finding linkage | services/field_assessment/connectors/ai_tool_discovery_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Cross-reference | scan_id passed to PR2 as pr1_scan_result_id | Implemented |
| Stranded output | None identified |

---

## ai_data_access_mapping (PR2)

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/ai_data_access_mapping/mapper.py | Implemented |
| Evidence record | FaScanResult with source_type=ai_data_access_mapping | Implemented |
| Finding linkage | services/field_assessment/connectors/ai_data_access_mapping_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Cross-reference | pr1_scan_result_id embedded in mappings | Implemented |
| Stranded output | None identified |

---

## external_ai_risk_register (PR3)

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/external_ai_risk_register/risk_engine.py | Implemented |
| Evidence record | FaScanResult with source_type=external_ai_risk_register + FaExternalAiRiskRecord per tool | Implemented |
| Finding linkage | services/field_assessment/connectors/external_ai_risk_register_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Cross-reference | pr1_scan_result_id + pr2_scan_result_id in every risk record | Implemented |
| Stranded output | None identified |

---

## ai_vendor_governance (PR4)

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/ai_vendor_governance/governance_engine.py | Implemented |
| Evidence record | FaScanResult + FaAiVendorGovernanceRecord per tool | Implemented |
| Finding linkage | services/field_assessment/connectors/ai_vendor_governance_bridge.py; 16 finding types | Implemented |
| Report inclusion | Via FaNormalizedFinding; also via governance records dashboard | Implemented |
| Cross-reference | pr1 + pr2 + pr3 scan IDs in every governance record | Implemented |
| Stranded output | None identified |

---

## network_scan

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/network_scan/runner.py::run_network_scan() | Implemented |
| Evidence record | FaScanResult with source_type=network_scan | Implemented |
| Finding linkage | services/field_assessment/connectors/network_scan_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Rejected targets provenance | Stored in FaVerifiedTarget + scan payload | Implemented |
| Stranded output | None identified |

---

## web_headers

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/web_headers/runner.py::run() | Implemented |
| Evidence record | FaScanResult with source_type=web_headers | Implemented |
| Finding linkage | services/field_assessment/connectors/web_headers_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Stranded output | web_headers runner does not emit scan_id/engagement_id — FA layer assigns these; raw payload is structurally complete but lacks self-describing provenance fields |

---

## dns_email

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/dns_email/runner.py::run() | Implemented |
| Evidence record | FaScanResult with source_type=dns_email | Implemented |
| Finding linkage | services/field_assessment/connectors/dns_email_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Stranded output | Same as web_headers: runner does not emit scan_id or engagement_id in payload |

---

## sharepoint_onedrive

| Step | Implementation | Status |
|------|---------------|--------|
| Scan execution | services/connectors/sharepoint/runner.py | Implemented |
| Evidence record | FaScanResult with source_type=sharepoint_onedrive | Implemented |
| Finding linkage | services/field_assessment/connectors/sharepoint_bridge.py | Implemented |
| Report inclusion | Via FaNormalizedFinding | Implemented |
| Stranded output | None identified |

---

## google_workspace / aws / azure / gcp (Registered-Only)

| Step | Status | Notes |
|------|--------|-------|
| Scan execution | NOT IMPLEMENTED | No runner |
| Evidence record | PARTIAL — manual import possible | Operator provides JSON payload |
| Finding linkage | PARTIAL — depends on normalized_payload findings field | Manual upload format |
| Report inclusion | Conditional — only if operator provides findings in upload | |
| Stranded output | Manual uploads without findings key will not generate any findings |

**Note for operators:** When uploading AWS/GCP/Azure scan results manually, include a `findings` array in the `normalized_payload` to ensure findings are extracted. Without this, the scan result exists as evidence but generates no report findings.

---

## Stranded Output Summary

| Scanner | Stranded? | Root Cause |
|---------|-----------|-----------|
| All Microsoft Graph chain | No | Full bridge + finding chain implemented |
| network_scan | No | Bridge implemented |
| sharepoint_onedrive | No | Bridge implemented |
| web_headers | Minor | Runner lacks self-describing provenance fields |
| dns_email | Minor | Runner lacks self-describing provenance fields |
| google_workspace | Conditional | Manual import only; findings depend on operator providing them |
| aws / azure / gcp | Conditional | Same as google_workspace |
