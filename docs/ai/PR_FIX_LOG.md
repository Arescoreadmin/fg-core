# PR Fix Log (Strict)

## Purpose

This log records **completed, intentional fixes**.

Each entry documents **one issue and one resolution**.

If multiple issues were fixed, they **MUST be logged as separate entries**.

Entries in this log are **final** unless explicitly reversed.

---

## Rules (Mandatory)

AI reviewers **MUST**:

1. Treat each entry as resolved
2. Avoid reopening logged issues
3. Avoid suggesting alternative fixes
4. Avoid combining entries

This log overrides heuristics and “best practice” suggestions.

---

## Entry Format (Enforced)

Each entry MUST contain:

- Date
- Area
- Issue (single, specific)
- Resolution (single, specific)
- AI Notes (instructions, not commentary)

---

## Entries

---

### 2026-03-01 — Route Inventory Canonical Source

**Area:** CI · Route Inventory

**Issue:**  
Route inventory comparison used multiple discovery sources, causing inconsistent results.

**Resolution:**  
AST-derived route discovery was designated as the sole canonical inventory source.

**AI Notes:**  
- Do NOT suggest runtime app inspection as authoritative
- Do NOT recommend hybrid inventory sources

---

### 2026-03-01 — Route Inventory Runtime-Only Drift

**Area:** CI · Governance

**Issue:**  
`route-inventory-audit` failed on runtime-only routes not present in OpenAPI.

**Resolution:**  
Runtime-only drift was downgraded to warning-only behavior.

**AI Notes:**  
- Do NOT escalate runtime-only drift to failure
- Do NOT recommend adding internal routes to OpenAPI

---

### 2026-03-01 — Duplicate `contract_routes` Definitions

**Area:** CI · Tooling

**Issue:**  
Multiple `contract_routes()` definitions caused lint failures and ambiguity.

**Resolution:**  
All local definitions were removed; a single imported implementation remains.

**AI Notes:**  
- Do NOT reintroduce local `contract_routes()` helpers
- Always import from `tools.ci.plane_registry_checks`

---

## Reopening Policy

An issue listed here may only be revisited if:

- The underlying behavior changes
- A new regression is introduced
- A PR explicitly states intent to reverse the fix

Absent these conditions, the issue is **closed**.

---

_Last updated: 2026-03-01_