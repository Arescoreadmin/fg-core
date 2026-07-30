# Top 10 Highest-ROI Actions

Ranked by (risk retired × credibility gained) ÷ engineering days. All ten fit inside the 18.5-day plan except #10 (founder time, 0 eng days).

| # | Action | Finding | Days | ROI | Why it wins |
|---|--------|---------|------|-----|-------------|
| 1 | **Anthropic auto-recharge + balance check** | FG-LR-013 | 0.1 | 9/10 at ~1hr | Cheapest insurance in the audit: prevents a report-generation failure in front of a client. Do it today. |
| 2 | **Full production dry run (H1–H18) on the current stack** | FG-LR-001 | 3.0 | 10 | Converts "should work" into "watched it work" across every launch-critical path; the July incident base-rate says it will find real defects while they're still free. |
| 3 | **Portal named-user proof with a real external mailbox** | FG-LR-002 | 2.0 | 10 | The only client door has never opened for a real client. Binary risk, fully retired in two days. |
| 4 | **Backup verification + one restore drill + runbook** | FG-LR-003 | 1.5 | 9 | Retires the one catastrophic-severity item; also instantly answers the enterprise DR question with evidence instead of silence. |
| 5 | **Portal launch-gating (hide stubs, trim nav, jargon tooltips)** | FG-LR-008 | 1.0 | 8 | One day converts "impressive but unfinished" into "focused and professional" on the surface that carries the fee. |
| 6 | **Report/PDF QA checklist on real dry-run data** | FG-LR-011 | 1.0 | 8 | The PDF is the artifact the buyer forwards to their board; one QA day protects the entire deliverable's credibility (FOUNDER_DIRECTIVE: legally-defensible standard). |
| 7 | **Incident/rollback runbook + timed drill** | FG-LR-005 | 1.0 | 8 | Converts proven-but-improvised recovery ability into repeatable process before a client is watching. |
| 8 | **Console launch-gating (≤9 nav items, one dashboard)** | FG-LR-007 | 2.0 | 7 | Halves operator surface, sharpens screen-shares, and cuts the launch-window QA area — pure subtraction. |
| 9 | **Infra headroom + concurrent load check + orphan-recovery observation** | FG-LR-004 | 1.0 | 8 | Retires the in-meeting stall, the most visible failure mode of the assessor-led model. |
| 10 | **Design-partner selection + engagement paper (price card, response-time expectation, DPA cross-check)** | commercial track | 0 eng | 9 | Engineering readiness without a scheduled client converts to nothing; this makes the date real. |

**Total engineering days for actions 1–9: 12.6** — inside the plan with room for the remaining P1 items (retention runbook 0.5, alert triage 0.5, secrets 1.0, docs truth 1.0, funnel hiding 0.5 = 3.5) and buffer (2.4). 12.6 + 3.5 + 2.4 = 18.5, matching the plan total.

## The one-line theory of this launch

Everything expensive is already built; everything missing is cheap. The ROI table is dominated by *verification and subtraction* because the marginal return on new construction is currently negative — each new surface adds QA area and operational load while the moat's compounding term sits at zero until client one (see `MOAT_ASSESSMENT.md`).
