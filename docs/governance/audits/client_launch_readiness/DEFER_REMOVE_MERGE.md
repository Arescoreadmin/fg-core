# Defer / Remove / Merge / Hide

Complexity is a cost. Everything below either failed to justify pre-launch time or actively dilutes the launch. "Hide" = gate from default visibility, keep code. "Freeze" = no further PRs until the stated trigger. "Remove" = delete after verification.

---

## HIDE for launch (cheap, in the 19-day plan)

| Item | Action | Why | Effort |
|------|--------|-----|--------|
| Console legacy decision-engine wing (decisions, forensics, alignment, provenance, corpus, retrieval, ingestion, evaluation-lab, policies, providers) | Hide via nav registry gating | Belongs to deferred Tier 3/4 products; dilutes operator focus; shows sparse data in client screen-shares | in FG-LR-007 (2d) |
| 3 of 4 console dashboards (executive-intelligence, operations-center, control-tower) | Hide; keep `/dashboard` as the one Home | Four "start here" pages is zero "start here" pages | in FG-LR-007 |
| Portal `/changes` | Hide (permanent-empty stub — `useState<ChangeGroup[]>([])` never set) | Dead end for a paying client | in FG-LR-008 (1d) |
| Portal `/export` unavailable options; Timeline/Trust/Continuity/Notifications/Actions as top-level nav | Hide/fold into Dashboard | 12-item nav for a 6-task user | in FG-LR-008 |
| Self-serve Tier-1 funnel (landing/onboarding/assessment wizard, Stripe checkout) | Hide public paths | Unstaffed paid product = brand risk; launch motion is assessor-led | FG-LR-023 (0.5d) |
| Identity governance panel beyond Users/Invitations/Audit tabs | Default-collapse the other ~17 tabs | Enterprise depth without hierarchy; no launch task needs them | fold into FG-LR-007 |

## FREEZE (no further investment until trigger)

| Item | Trigger to unfreeze | Why freeze |
|------|--------------------|------------|
| Trust-layer expansion arc (open PRs 1.6+, replay engine 1.10, further authority layers) | A client, prospect, or regulator asks for replay proofs / deeper verification | Already deeper than any first-10 client will evaluate; every day here is a day not spent on ops gaps (FG-LR-024) |
| Enterprise KMS stub providers (AWS/Azure/Google/Vault/PKCS#11/HSM — all NotImplementedError) | First enterprise deal naming KMS in security requirements | 256 tests over stubs is investment ahead of any demand signal (FG-LR-021) |
| CGIN benchmark/intelligence extensions | ≥10 consenting tenants | Benchmarks without tenant volume are empty math |
| Subscription/billing v2 + capability metering (open P1.2–P1.5 PRs, placeholder PR numbers) | Client ~10 / recurring-revenue contracts | Invoice manually; metering before revenue is inverted priority (FG-LR-022). Exception: land anything gating portal features already in use, then stop |
| New bounded contexts (91 service packages exist) | Post-launch architecture review | Surface area is the largest hidden operational cost in the repo |
| Additional scan connectors beyond the 13 | First client segment that needs one (e.g., Google Workspace shop) | Depth of delivery > breadth of scanners for M365-centric targets |

## MERGE / CONSOLIDATE (post-launch)

| Item | Action |
|------|--------|
| Open WIP PR sprawl (identity P1.x series, PR-SIGN 416, provenance 1.x, PR 535, assurance engine) | Land or close each before Stage 2 — WIP drift against a moving main is itself a risk (FG-LR-024) |
| Four dashboards | After launch, merge the useful widgets of the hidden three into the one Home |
| `api/field_assessment.py` (12,747 lines) | Split by resource post-launch, contract-frozen (FG-LR-015) |
| Duplicate app trees (`console/` legacy per SYSTEM.md, `ui/`, `main/`, `backend/` vs `apps/*`) | Mark dead or delete in the hygiene sweep (FG-LR-018) |
| SYSTEM.md/STATUS/CLIENT_READINESS/ROADMAP truth | One reconciliation pass now (FG-LR-009); keep ROADMAP as the single PR ledger |

## REMOVE (after verification, post-launch)

| Item | Precondition |
|------|--------------|
| Legacy `/remediation/*` routes (17, deprecated) | 30 days of zero traffic (FG-LR-025) |
| Legacy `ok:{exp}` session parsing in portal `verifySessionToken` | Confirm no legacy cookies in the wild post-cutover |
| `frostgate_decisions.db-shm` and any runtime artifacts in git | Immediate, zero risk (part of FG-LR-018) |
| Root-level stale planning docs (~25 .md files: ALIGNMENT_AUDIT, POST_PT_AUDIT, frostgate_tree_everything.txt, …) | Archive to docs/archive/ in hygiene sweep |
| `admin_gateway` (conditional) | Only if the FG-LR-019 topology decision is "BFF→core is the prod path" — then either deploy it with a purpose or excise the prod-dead flows |

## Explicitly KEEP (challenged and retained)

- **Portal Assistant (governed AI workspace)** — differentiator per FOUNDER_DIRECTIVE; already QA-approval-gated; keep conditional.
- **Verification bundle panel (console + portal)** — client-visible trust artifact; cheap to keep, sells the moat.
- **Workforce intelligence** — live data, sellable now, feeds the AI-governance story.
- **Durable job service, evidence lifecycle, decision ledger** — operational spine; not negotiable.
- **The 6 authoritative root docs** (CLAUDE, SYSTEM, ROADMAP, BLUEPRINT_STAGED, FOUNDER_DIRECTIVE, CLIENT_READINESS) — with the FG-LR-009 truth pass.
