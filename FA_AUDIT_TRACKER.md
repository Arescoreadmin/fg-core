# Field Assessment Audit Tracker

Forensic audit completed 2026-06-02. 19 issues + 3 competitive differentiators.
Status: `open` | `in_progress` | `done` | `deferred`

---

## Sprint 1 — Security + Quick Wins (ROI: highest, effort: lowest)

| # | ID | Title | Priority | Est | Status | PR |
|---|----|-------|----------|-----|--------|----|
| 1 | 4.1 | QA approval list doesn't auto-refresh after approving | P1 | 30min | open | — |
| 2 | 3.1 | Blocking gate missing-item IDs truncated to 8 chars — ambiguous | P1 | 30min | open | — |
| 3 | 2.3 | Race condition: discard recording while transcription is in-flight | P1 | 1h | open | — |
| 4 | 1.1 | No sector badge in interview UI — assessor doesn't know which sector is active | P1 | 1h | open | — |
| 5 | 7.1 | Audio blob storage path predictable — enumerate other engagements' recordings | P1 | 1h | open | — |
| 6 | 7.2 | QA approval requires only `governance:write` — no segregation of duties | P1 | 2h | open | — |
| 7 | 2.2 | Blob upload fails silently when Whisper succeeds — orphaned storage + no feedback | P1 | 2h | open | — |

---

## Sprint 2 — Data Integrity + Missing Core Features

| # | ID | Title | Priority | Est | Status | PR |
|---|----|-------|----------|-----|--------|----|
| 8 | 1.2 | Backend doesn't validate interview role belongs to engagement's playbook | P1 | 2h | open | — |
| 9 | 5.3 | Observation domain mapping silently drops controls if domain key is unknown | P1 | 2h | open | — |
| 10 | 6.1 | `_audio_*` structured_evidence keys not validated on backend | P1 | 3h | open | — |
| 11 | 4.2 | Client access code lost on page refresh — no way to retrieve it | P2 | 4h | open | — |
| 12 | 5.2 | CMMC controls appear on non-CMMC engagements — no framework filtering | P2 | 3h | open | — |
| 13 | 8.3 | No engagement type validation at creation — assessment_type can mismatch playbook | P1 | 3h | open | — |
| 14 | 8.1 | No bulk observation import — can't migrate from spreadsheets or other tools | P1 | 6h | open | — |

---

## Sprint 3 — Full CRUD + Competitive Features

| # | ID | Title | Priority | Est | Status | PR |
|---|----|-------|----------|-----|--------|----|
| 15 | 2.1 | No observation editing after capture — immutable once submitted | P2 | 8h | open | — |
| 16 | 2.4 | No soft-delete for observations — bad captures stick forever | P2 | 6h | open | — |
| 17 | 6.2 | No cascade-delete evidence links when observation is deleted | P2 | 3h | open | — |
| 18 | 8.2 | No observation change history — audit trail shows capture only | P2 | 5h | open | — |
| 19 | 8.4 | No interview reuse/templating from prior engagements | P2 | 6h | open | — |

---

## Competitive Differentiators (moat builders)

| # | ID | Title | Est | Status |
|---|----|-------|-----|--------|
| A | DIFF-1 | Show exact regulation clause (HIPAA §164.308) per interview question — not just NIST | 4h | open |
| B | DIFF-2 | Post-transcription Claude pass: extract entities → auto-link to findings | 8h | open |
| C | DIFF-3 | Clickable control gap matrix — click a control → see observations + evidence inline | 6h | open |

---

## Completed

| Date | ID | Title | PR |
|------|----|-------|----|
| 2026-06-01 | — | QA approval reviewer name + confirmation step | eb229c58 |
| 2026-06-01 | — | Evidence lineage crash (reserved `ref` prop) + compiled-by input | 32ae24f1 |
| 2026-06-01 | — | Control gap matrix: obs-derived, CMMC added, key normalization | 4a616ff0 |
| 2026-06-01 | — | Blocking gate navigation links | 4a616ff0 |
| 2026-06-02 | — | Persist + replay interview audio recordings via Vercel Blob | 1e730e43 |
