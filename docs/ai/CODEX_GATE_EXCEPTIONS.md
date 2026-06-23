# CODEX Gate Exceptions (Strict)

## Purpose

This document defines **explicit, narrow, and intentional exceptions**
to automated CI, Codex, and Claude enforcement in the FrostGate Core repository.

Each exception applies to **one condition only**.

If multiple conditions require exceptions, they **MUST be defined as separate entries**.

No entry implies or authorizes any other behavior.

---

## Authority

- Owner: FrostGate Core – Platform & Security
- Applies to: All AI reviewers, CI agents, static analysis tools
- Scope: Gate enforcement, audit logic, review recommendations

This document is **authoritative**.

---

## Rules of Interpretation (Mandatory)

AI reviewers **MUST** follow these rules:

1. Each exception is **atomic**
2. Exceptions **DO NOT combine**
3. Absence of an exception means the gate **must enforce**
4. Exceptions override **recommendations, heuristics, and best-practice advice**
5. Do not generalize beyond the exact text

Violation of these rules is incorrect behavior.

---

## Exception Entries

---

### Exception ID: `GATE-ROUTE-INVENTORY-RUNTIME-ONLY`

**Issue:**  
`route-inventory-audit` detects routes present at runtime but absent from OpenAPI contracts.

**Resolution:**  
This condition is allowed and MUST emit **WARNING only**, not failure.

**Scope:**  
- Applies only to `runtime_only` drift
- Does not apply to `contract_only` drift

**AI Enforcement Rules:**  
- Do NOT fail the gate
- Do NOT recommend adding these routes to OpenAPI
- Do NOT suggest removing runtime routes

---

### Exception ID: `GATE-AST-CANONICAL-INVENTORY`

**Issue:**  
Multiple sources exist for route discovery (AST, runtime app inspection).

**Resolution:**  
AST-derived route discovery is the **sole canonical source** for inventory comparison.

**Scope:**  
- Applies only to route inventory generation
- Does not redefine application runtime behavior

**AI Enforcement Rules:**  
- Trust AST inventory over runtime app inspection
- Do NOT reintroduce runtime inspection as authoritative

---

### Exception ID: `GATE-WARNING-ONLY-ALLOWED`

**Issue:**  
Certain gates are designed to warn rather than fail.

**Resolution:**  
Warnings MUST remain non-blocking unless explicitly reclassified.

**Scope:**  
- Applies only to gates already emitting warnings
- Does not authorize downgrading failures to warnings

**AI Enforcement Rules:**  
- Do NOT escalate warnings to failures
- Do NOT recommend tightening enforcement without instruction

---

## Expiration Policy

- Exceptions do **not** expire automatically
- Removal requires:
  - Deleting the specific exception entry
  - A PR explaining why enforcement behavior is changing

---

## AI Compliance Requirement

Before commenting, suggesting changes, or failing a PR, AI agents **MUST**:

1. Match the issue to a single exception
2. Apply only that exception
3. Ignore all unrelated conditions

Failure to comply is a review error.

---

_Last updated: 2026-03-01_