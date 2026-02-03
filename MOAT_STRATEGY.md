# FrostGate-Core — Moat & Competitive Strategy

This document explains *why* the architecture exists, not *what* it must do.

Authoritative requirements live in `BLUEPRINT_STAGED.md`.

---

## Market Reality
Competitors optimize for:
- Speed of onboarding
- Superficial simplicity
- Report generation

They avoid:
- Evidence integrity
- Deterministic replay
- Governance rigor

---

## FrostGate Moats

### Moat 1 — Evidence Gravity
- Cryptographically verifiable evidence chains
- Replayable decisions
- Independent verification

Switching cost = evidence history.

---

### Moat 2 — Continuous Compliance
- Drift detected automatically
- Controls continuously evaluated
- POA&M generated from evidence

Audits become exports, not projects.

---

### Moat 3 — Control-Plane Supremacy
- Firewalls, CI, cloud config, runtimes all become modules
- Governance is centralized
- Policy is authoritative

Others bolt on compliance. FrostGate owns it.

---

### Moat 4 — Contractual Gravity
- API, event, artifact schemas become standards
- Partners integrate to FrostGate formats
- Auditors learn FrostGate verification flow

---

### Moat 5 — Proof Speed
Auditor: “Prove X.”  
FrostGate: `verify_bundle → hash → done.`  
Competitors: meetings.

---

## Non-Goals
- Winning on lowest price
- Competing with SIEM dashboards
- Being “easy” at the cost of rigor

---

This document informs strategy only.  
It does not define requirements.
