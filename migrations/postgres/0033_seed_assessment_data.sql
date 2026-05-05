-- 0033_seed_assessment_data.sql
-- Seeds the base question bank (35 questions across 6 domains) and
-- the three AI prompt templates (executive, technical, compliance).
-- Questions are profile-type-agnostic (used across all profiles).
-- Profile-specific weight modifiers are applied at score time in the service layer.

-- ─── Question bank ────────────────────────────────────────────────────────────

INSERT INTO assessment_schemas (schema_version, profile_type, is_current, questions)
VALUES (
  'v2025.1-base',
  'base',
  TRUE,
  '[
    {
      "id": "dg_001",
      "domain": "data_governance",
      "text": "Does your organization have a formal data classification policy that covers AI-processed data?",
      "type": "boolean",
      "weight": 1.5
    },
    {
      "id": "dg_002",
      "domain": "data_governance",
      "text": "How would you rate the completeness of your organization'\''s inventory of data used in AI workflows?",
      "type": "scale",
      "weight": 1.2
    },
    {
      "id": "dg_003",
      "domain": "data_governance",
      "text": "Does your organization conduct regular data quality assessments for data used in AI systems?",
      "type": "boolean",
      "weight": 1.0
    },
    {
      "id": "dg_004",
      "domain": "data_governance",
      "text": "How are data retention and deletion policies applied to AI system outputs?",
      "type": "select",
      "options": ["No policy exists", "Ad-hoc, case by case", "Documented but unenforced", "Consistently enforced", "Audited and certified"],
      "weight": 1.3
    },
    {
      "id": "dg_005",
      "domain": "data_governance",
      "text": "Does your organization track the lineage of data used in AI systems (where data came from, how it was transformed)?",
      "type": "boolean",
      "weight": 1.0
    },
    {
      "id": "dg_006",
      "domain": "data_governance",
      "text": "Is there a documented process for handling data subject rights requests that extends to AI-processed data?",
      "type": "boolean",
      "weight": 1.1
    },
    {
      "id": "sp_001",
      "domain": "security_posture",
      "text": "Does your organization have documented security policies that specifically address AI tools and services?",
      "type": "boolean",
      "weight": 1.5
    },
    {
      "id": "sp_002",
      "domain": "security_posture",
      "text": "Are AI tools and applications subject to the same vulnerability management process as other software?",
      "type": "boolean",
      "weight": 1.2
    },
    {
      "id": "sp_003",
      "domain": "security_posture",
      "text": "Does your organization conduct security assessments or penetration tests specifically for AI systems?",
      "type": "boolean",
      "weight": 1.1
    },
    {
      "id": "sp_004",
      "domain": "security_posture",
      "text": "How would you rate the strength of your access controls for AI systems and APIs?",
      "type": "scale",
      "weight": 1.3
    },
    {
      "id": "sp_005",
      "domain": "security_posture",
      "text": "Does your organization monitor AI system outputs for anomalies, prompt injection, or misuse?",
      "type": "boolean",
      "weight": 1.2
    },
    {
      "id": "sp_006",
      "domain": "security_posture",
      "text": "Are AI provider API keys and credentials managed through a secrets management system (not stored in code or email)?",
      "type": "boolean",
      "weight": 1.4
    },
    {
      "id": "am_001",
      "domain": "ai_maturity",
      "text": "Does your organization have a formal AI governance policy or acceptable use policy communicated to all staff?",
      "type": "boolean",
      "weight": 1.5
    },
    {
      "id": "am_002",
      "domain": "ai_maturity",
      "text": "Approximately how many AI tools or services are actively used by employees (including ChatGPT, Copilot, Claude, etc.)?",
      "type": "select",
      "options": ["None — AI tools are not permitted", "1–3 tools", "4–10 tools", "11–25 tools", "More than 25 tools"],
      "weight": 1.0
    },
    {
      "id": "am_003",
      "domain": "ai_maturity",
      "text": "Is there a designated person or team responsible for AI governance decisions?",
      "type": "boolean",
      "weight": 1.2
    },
    {
      "id": "am_004",
      "domain": "ai_maturity",
      "text": "Does your organization evaluate AI vendors for security and compliance before deployment?",
      "type": "boolean",
      "weight": 1.1
    },
    {
      "id": "am_005",
      "domain": "ai_maturity",
      "text": "How would you rate your organization'\''s overall awareness of AI-related risks?",
      "type": "scale",
      "weight": 1.0
    },
    {
      "id": "am_006",
      "domain": "ai_maturity",
      "text": "Does your organization have a process for employees to report concerns about AI use?",
      "type": "boolean",
      "weight": 0.9
    },
    {
      "id": "ir_001",
      "domain": "infra_readiness",
      "text": "Is multi-factor authentication (MFA) enforced for access to AI tools and services?",
      "type": "boolean",
      "weight": 1.5
    },
    {
      "id": "ir_002",
      "domain": "infra_readiness",
      "text": "Does your organization use a password manager or privileged access management (PAM) system?",
      "type": "boolean",
      "weight": 1.2
    },
    {
      "id": "ir_003",
      "domain": "infra_readiness",
      "text": "Are AI service integrations (APIs, webhooks) protected by transport-layer encryption (TLS 1.2 or higher)?",
      "type": "boolean",
      "weight": 1.3
    },
    {
      "id": "ir_004",
      "domain": "infra_readiness",
      "text": "Does your organization maintain network segmentation or access boundaries that include AI workloads?",
      "type": "boolean",
      "weight": 1.0
    },
    {
      "id": "ir_005",
      "domain": "infra_readiness",
      "text": "How would you rate your organization'\''s incident response readiness for an AI-related data exposure event?",
      "type": "scale",
      "weight": 1.2
    },
    {
      "id": "ca_001",
      "domain": "compliance_awareness",
      "text": "Has your organization identified which AI use cases may trigger regulatory requirements (HIPAA, FFIEC, CMMC, etc.)?",
      "type": "boolean",
      "weight": 1.5
    },
    {
      "id": "ca_002",
      "domain": "compliance_awareness",
      "text": "Does your organization maintain executed vendor agreements (BAAs, DPAs) with AI providers that process sensitive data?",
      "type": "boolean",
      "weight": 1.4
    },
    {
      "id": "ca_003",
      "domain": "compliance_awareness",
      "text": "Has your organization conducted a formal risk assessment specifically addressing AI adoption?",
      "type": "boolean",
      "weight": 1.3
    },
    {
      "id": "ca_004",
      "domain": "compliance_awareness",
      "text": "Does your organization have a formal compliance program that addresses AI risks?",
      "type": "boolean",
      "weight": 1.2
    },
    {
      "id": "ca_005",
      "domain": "compliance_awareness",
      "text": "How would you rate your compliance team'\''s understanding of AI-specific regulatory requirements?",
      "type": "scale",
      "weight": 1.0
    },
    {
      "id": "ca_006",
      "domain": "compliance_awareness",
      "text": "Does your organization have an AI ethics or responsible AI use framework?",
      "type": "boolean",
      "weight": 0.9
    },
    {
      "id": "ap_001",
      "domain": "automation_potential",
      "text": "Does your organization have standardized, repeatable workflows that could benefit from AI automation?",
      "type": "boolean",
      "weight": 1.0
    },
    {
      "id": "ap_002",
      "domain": "automation_potential",
      "text": "Are there documented manual review processes where AI assistance could reduce risk or error rate?",
      "type": "boolean",
      "weight": 1.0
    },
    {
      "id": "ap_003",
      "domain": "automation_potential",
      "text": "Does your organization have a formal process for evaluating new AI capabilities before adoption?",
      "type": "boolean",
      "weight": 1.1
    },
    {
      "id": "ap_004",
      "domain": "automation_potential",
      "text": "How would you rate your organization'\''s technical infrastructure readiness to support AI automation at scale?",
      "type": "scale",
      "weight": 1.0
    },
    {
      "id": "ap_005",
      "domain": "automation_potential",
      "text": "Does your organization have active leadership buy-in and budget allocated for responsible AI investment?",
      "type": "boolean",
      "weight": 1.1
    }
  ]'::jsonb
)
ON CONFLICT (schema_version) DO NOTHING;

-- ─── Prompt templates ─────────────────────────────────────────────────────────

INSERT INTO prompt_versions (prompt_key, version, is_active, system_prompt, user_prompt_template) VALUES
(
  'executive_report',
  'v1.0',
  TRUE,
  'You are an AI governance advisor generating an executive-level advisory report for a regulated organization. Your audience is C-suite and board members. Use business language, avoid technical jargon. Be direct about risks. Never say "certified" — always say "aligned with" or "designed to support compliance with". Return a single valid JSON object matching the exact schema provided.',
  'Generate an executive AI governance advisory report for the following organization.

Organization: {{org_name}}
Industry: {{industry}}
Profile Type: {{profile_type}}
Overall Risk Score: {{overall_score}}/100
Risk Band: {{risk_band}}

Domain Scores:
{{domain_scores}}

Respond with ONLY a valid JSON object in this exact structure — no markdown, no explanation, just the JSON:
{
  "executive_summary": "2-3 paragraph executive summary of AI governance risk posture and business implications",
  "key_strengths": ["strength 1", "strength 2", "strength 3"],
  "critical_gaps": ["gap 1", "gap 2", "gap 3", "gap 4", "gap 5"],
  "domain_findings": {
    "data_governance": "1-2 sentence finding",
    "security_posture": "1-2 sentence finding",
    "ai_maturity": "1-2 sentence finding",
    "infra_readiness": "1-2 sentence finding",
    "compliance_awareness": "1-2 sentence finding",
    "automation_potential": "1-2 sentence finding"
  },
  "roadmap": {
    "days_30": [
      {"title": "action title", "description": "description", "effort": "Low|Medium|High", "impact": "Low|Medium|High"}
    ],
    "days_60": [
      {"title": "action title", "description": "description", "effort": "Low|Medium|High", "impact": "Low|Medium|High"}
    ],
    "days_90": [
      {"title": "action title", "description": "description", "effort": "Low|Medium|High", "impact": "Low|Medium|High"}
    ]
  },
  "framework_alignments": [
    {"framework": "NIST AI RMF", "alignment_pct": 0, "gap_count": 0, "notes": "brief note"},
    {"framework": "SOC 2 Type II", "alignment_pct": 0, "gap_count": 0, "notes": "brief note"}
  ],
  "disclaimer": "This report reflects alignment with, not certification to, referenced frameworks. It is intended as an advisory tool to support internal risk management decisions."
}'
),
(
  'technical_report',
  'v1.0',
  TRUE,
  'You are an AI governance advisor generating a technical advisory report for a CISO or CTO. Your audience understands security and technology concepts. Be specific about controls, gaps, and implementation steps. Reference specific frameworks and control IDs where relevant. Never say "certified" — always say "aligned with". Return a single valid JSON object.',
  'Generate a technical AI governance advisory report for the following organization.

Organization: {{org_name}}
Industry: {{industry}}
Profile Type: {{profile_type}}
Overall Risk Score: {{overall_score}}/100
Risk Band: {{risk_band}}

Domain Scores:
{{domain_scores}}

Respond with ONLY a valid JSON object matching the exact same schema as the executive report but with technical depth: specific control names, CVE references where relevant, implementation steps rather than business language. Include framework_alignments for the frameworks most relevant to {{industry}} and {{profile_type}}.'
),
(
  'compliance_report',
  'v1.0',
  TRUE,
  'You are an AI governance advisor generating a compliance-oriented advisory report for a CCO, legal counsel, or external auditor. Use audit artifact language. Be precise about obligations, evidence gaps, and regulatory exposure. Never say "certified" or "compliant with" — always say "aligned with" or "designed to support compliance with". Return a single valid JSON object.',
  'Generate a compliance-focused AI governance advisory report for the following organization.

Organization: {{org_name}}
Industry: {{industry}}
Profile Type: {{profile_type}}
Overall Risk Score: {{overall_score}}/100
Risk Band: {{risk_band}}

Domain Scores:
{{domain_scores}}

Respond with ONLY a valid JSON object matching the executive report schema but with compliance depth: cite specific regulatory provisions, evidence requirements, audit readiness gaps, and remediation priority by regulatory obligation.'
)
ON CONFLICT (prompt_key, version) DO NOTHING;

INSERT INTO schema_migrations(version) VALUES ('0033') ON CONFLICT DO NOTHING;
