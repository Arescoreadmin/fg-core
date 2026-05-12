# Provenance Validation UI (PR 48)

## Purpose

PR 48 adds a provenance validation UI component that makes provenance decisions
understandable to operators, auditors, compliance reviewers, and legal reviewers.

This is trust infrastructure UX. It does not change provenance enforcement logic,
retrieval behavior, policy behavior, AI answer generation, or provider routing.

## Component

`console/components/governance/ProvenanceValidationPanel.tsx`

Exported from `console/components/governance/index.ts`.

## Provenance States

The panel renders all four canonical provenance reason codes from the enforcement layer:

| Code | Label | Trust Level |
|------|-------|-------------|
| `PROVENANCE_VALID` | Provenance Valid | trusted |
| `PROVENANCE_SOURCE_NOT_RETRIEVED` | Provenance Invalid — Source Not Retrieved | untrusted |
| `PROVENANCE_SOURCE_NOT_IN_PROMPT` | Provenance Invalid — Source Not In Prompt | untrusted |
| `PROVENANCE_NO_CONTEXT_AVAILABLE` | No Context Available | no_context |
| null | Provenance Unavailable | unavailable |
| unknown code | Unknown status: `<code>` | unavailable |

Unknown reason codes render safely with a warning label. No hidden failure states.

## Trust Level Derivation

`deriveTrustLevel(status)` maps status codes deterministically:

- `PROVENANCE_VALID` → `trusted`
- `PROVENANCE_NO_CONTEXT_AVAILABLE` → `no_context` (not a trust failure — answer had no citations)
- `PROVENANCE_SOURCE_NOT_RETRIEVED` → `untrusted`
- `PROVENANCE_SOURCE_NOT_IN_PROMPT` → `untrusted`
- null / unrecognized → `unavailable` (conservative)

## Citation Validation

Citations are grouped by status and rendered in deterministic order:

1. Invalid / Rejected (first — highest visibility for operators)
2. Valid
3. Unavailable / Unknown

Each citation card renders:
- Validation status (text label + icon, not color-only)
- Citation ID, source ID, chunk ID, document ID, corpus ID (where available)
- Retrieved state, included-in-prompt state, cited state
- Rejection reason: machine-readable code + human-readable explanation

## Retrieved / Prompt-Included / Cited Distinction

The chunk breakdown section shows three counts:

- **Retrieved**: all chunks returned by the retrieval pipeline
- **In Prompt**: chunks with `included_in_prompt = true` (actually sent to the AI)
- **Cited**: chunks whose IDs appear in `citation_source_ids`

The distinction note is always visible:
> "Retrieved ≠ Included in prompt. Included ≠ Cited. Cited ≠ Valid."

A per-chunk table shows the Retrieved / In Prompt / Cited state for each chunk.

## Export-Safe Summary

`buildProvenanceExportSummary(data)` returns a payload containing:

- `provenance_status`
- `trust_level`
- `citation_count`
- `invalid_citation_count`
- `prompt_included_chunk_count`
- `retrieved_chunk_count`
- `used_rag`
- `context_count`
- `retrieval_trace_id`
- `retrieval_strategy`
- `export_safe: true`
- `generated_at`

Never includes: raw vectors, raw prompts, raw chunk text, provider payloads, credentials.

## Legal / Compliance Language

All UI language is conservative and audit-safe:

- "Citation rejected: source was not retrieved for this request."
- "Source was retrieved but not included in the prompt context."
- "No relevant context was available."
- "Provenance trust status could not be determined."

No language implies legal approval. Legal review mode is a future placeholder, clearly
marked "not yet available" with no fabricated data.

## Future Placeholders

The panel includes collapsed, clearly-labelled placeholders for:

- Evidence graph
- Answer-to-source mapping
- Legal review mode
- Citation lineage
- Exportable legal packet

All placeholders are marked "not yet available" and contain no fake data.

## Safety Invariants

- No `dangerouslySetInnerHTML`
- No raw vectors, raw prompts, provider internals, or credentials exposed
- No fake citations, fake legal approval, or fake evidence graph
- `role="alert"` only on invalid/high-risk states
- All icons are `aria-hidden="true"`; text labels always accompany status icons
- Deterministic citation ordering via `sortCitations()`
- Safe fallback for null, malformed, or partial payloads

## Integration

- `/dashboard/provenance` — integrated as the primary provenance explorer route
- `console/components/governance/index.ts` — exported for reuse in other views

## Non-Goals

- Does not change provenance enforcement logic
- Does not change retrieval behavior
- Does not change policy behavior
- Does not add backend endpoints
- Does not generate legal advice
