-- 0059_question_bank_v2_nist_mapped.sql
--
-- Upgrades the assessment schema from v2025.1-base (35 questions, 6 domains)
-- to v2025.2-nist-mapped (55 questions, 7 domains).
--
-- Changes:
--   - Every question carries a nist_control_id mapped to a specific NIST AI RMF
--     subcategory (GOVERN x.y, MAP x.y, MEASURE x.y, MANAGE x.y).
--   - New domain: ai_trustworthiness (8 questions) covering NIST trustworthiness
--     characteristics: bias, fairness, explainability, privacy, human oversight.
--   - 21 new questions filling MAP and MEASURE gaps identified in gap analysis.
--   - Prompt templates upgraded to v2.0: include NIST control context, risk
--     quantification section, specific vendor/cost roadmap items, and
--     nist_function_findings narrative block.

-- ─── Retire old schema ────────────────────────────────────────────────────────
UPDATE assessment_schemas SET is_current = FALSE WHERE schema_version = 'v2025.1-base';

-- ─── Question bank v2 ─────────────────────────────────────────────────────────
INSERT INTO assessment_schemas (schema_version, profile_type, is_current, questions)
VALUES (
  'v2025.2-nist-mapped',
  'base',
  TRUE,
  '[
    {
      "id": "dg_001",
      "domain": "data_governance",
      "text": "Does your organization have a formal data classification policy that covers AI-processed data?",
      "type": "boolean",
      "weight": 1.5,
      "nist_control_id": "GOVERN 1.1"
    },
    {
      "id": "dg_002",
      "domain": "data_governance",
      "text": "How would you rate the completeness of your organization''s inventory of data used in AI workflows?",
      "type": "scale",
      "weight": 1.2,
      "nist_control_id": "MAP 1.5"
    },
    {
      "id": "dg_003",
      "domain": "data_governance",
      "text": "Does your organization conduct regular data quality assessments for data used in AI systems?",
      "type": "boolean",
      "weight": 1.0,
      "nist_control_id": "MEASURE 2.5"
    },
    {
      "id": "dg_004",
      "domain": "data_governance",
      "text": "How are data retention and deletion policies applied to AI system outputs?",
      "type": "select",
      "options": ["No policy exists", "Ad-hoc, case by case", "Documented but unenforced", "Consistently enforced", "Audited and reviewed annually"],
      "weight": 1.3,
      "nist_control_id": "GOVERN 1.2"
    },
    {
      "id": "dg_005",
      "domain": "data_governance",
      "text": "Does your organization track the lineage of data used in AI systems (where data came from, how it was transformed)?",
      "type": "boolean",
      "weight": 1.0,
      "nist_control_id": "MAP 2.3"
    },
    {
      "id": "dg_006",
      "domain": "data_governance",
      "text": "Is there a documented process for handling data subject rights requests that extends to AI-processed data?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "MEASURE 2.10"
    },
    {
      "id": "dg_007",
      "domain": "data_governance",
      "text": "Does your organization maintain a register or inventory of all AI systems currently in production use, including third-party tools?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "MAP 3.1"
    },
    {
      "id": "dg_008",
      "domain": "data_governance",
      "text": "Is the origin, composition, and known limitations of data used to train or fine-tune AI systems documented?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "MAP 2.3"
    },
    {
      "id": "sp_001",
      "domain": "security_posture",
      "text": "Does your organization have documented security policies that specifically address AI tools and services?",
      "type": "boolean",
      "weight": 1.5,
      "nist_control_id": "GOVERN 2.2"
    },
    {
      "id": "sp_002",
      "domain": "security_posture",
      "text": "Are AI tools and applications subject to the same vulnerability management process as other software?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "MANAGE 1.3"
    },
    {
      "id": "sp_003",
      "domain": "security_posture",
      "text": "Does your organization conduct security assessments or penetration tests specifically targeting AI systems and APIs?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "MEASURE 2.8"
    },
    {
      "id": "sp_004",
      "domain": "security_posture",
      "text": "How would you rate the strength of your access controls for AI systems and APIs?",
      "type": "scale",
      "weight": 1.3,
      "nist_control_id": "GOVERN 2.2"
    },
    {
      "id": "sp_005",
      "domain": "security_posture",
      "text": "Does your organization monitor AI system outputs for anomalies, prompt injection, or misuse?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "MEASURE 2.9"
    },
    {
      "id": "sp_006",
      "domain": "security_posture",
      "text": "Are AI provider API keys and credentials managed through a secrets management system (not stored in code or email)?",
      "type": "boolean",
      "weight": 1.4,
      "nist_control_id": "MANAGE 2.4"
    },
    {
      "id": "sp_007",
      "domain": "security_posture",
      "text": "Does your organization have a documented testing protocol that AI systems must pass before being deployed into production use?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "MEASURE 1.1"
    },
    {
      "id": "sp_008",
      "domain": "security_posture",
      "text": "Has your organization tested AI systems for adversarial inputs, prompt injection attacks, or attempts to extract sensitive training data?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "MEASURE 2.3"
    },
    {
      "id": "am_001",
      "domain": "ai_maturity",
      "text": "Does your organization have a formal AI governance policy or acceptable use policy communicated to all staff?",
      "type": "boolean",
      "weight": 1.5,
      "nist_control_id": "GOVERN 1.1"
    },
    {
      "id": "am_002",
      "domain": "ai_maturity",
      "text": "Approximately how many AI tools or services are actively used by employees (including ChatGPT, Copilot, Claude, etc.)?",
      "type": "select",
      "options": ["None — AI tools are not permitted", "1–3 tools", "4–10 tools", "11–25 tools", "More than 25 tools"],
      "weight": 1.0,
      "nist_control_id": "MAP 3.5"
    },
    {
      "id": "am_003",
      "domain": "ai_maturity",
      "text": "Is there a designated person or team responsible for AI governance decisions and risk oversight?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "GOVERN 1.2"
    },
    {
      "id": "am_004",
      "domain": "ai_maturity",
      "text": "Does your organization formally evaluate AI vendors for security, compliance, and data handling before deployment?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "MAP 3.5"
    },
    {
      "id": "am_005",
      "domain": "ai_maturity",
      "text": "How would you rate your organization''s overall awareness of AI-related risks across leadership and staff?",
      "type": "scale",
      "weight": 1.0,
      "nist_control_id": "MAP 2.2"
    },
    {
      "id": "am_006",
      "domain": "ai_maturity",
      "text": "Does your organization have a process for employees to report concerns or incidents related to AI use?",
      "type": "boolean",
      "weight": 0.9,
      "nist_control_id": "GOVERN 1.7"
    },
    {
      "id": "am_007",
      "domain": "ai_maturity",
      "text": "Are end users, customers, or employees clearly informed when they are interacting with or affected by an AI system?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "GOVERN 1.7"
    },
    {
      "id": "am_008",
      "domain": "ai_maturity",
      "text": "Is there a named individual or role that is personally accountable when an AI system produces a harmful or incorrect outcome?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "GOVERN 1.2"
    },
    {
      "id": "am_009",
      "domain": "ai_maturity",
      "text": "How would you rate your organization''s culture of responsible AI use — are employees actively rewarded for raising AI concerns?",
      "type": "scale",
      "weight": 1.1,
      "nist_control_id": "GOVERN 1.5"
    },
    {
      "id": "am_010",
      "domain": "ai_maturity",
      "text": "Does your organization have a documented process for retiring or decommissioning AI systems, including data deletion and access revocation?",
      "type": "boolean",
      "weight": 1.0,
      "nist_control_id": "MANAGE 3.3"
    },
    {
      "id": "at_001",
      "domain": "ai_trustworthiness",
      "text": "Has your organization evaluated AI systems for potential bias or discriminatory outcomes against protected characteristics (race, gender, age, disability)?",
      "type": "boolean",
      "weight": 1.5,
      "nist_control_id": "MEASURE 2.4"
    },
    {
      "id": "at_002",
      "domain": "ai_trustworthiness",
      "text": "Can your AI systems explain or justify their outputs or recommendations to users in understandable terms?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "MEASURE 2.6"
    },
    {
      "id": "at_003",
      "domain": "ai_trustworthiness",
      "text": "Has a formal privacy impact assessment been conducted for AI systems that process personal or sensitive information?",
      "type": "boolean",
      "weight": 1.4,
      "nist_control_id": "MEASURE 2.10"
    },
    {
      "id": "at_004",
      "domain": "ai_trustworthiness",
      "text": "What level of human oversight exists when AI systems inform high-stakes decisions (hiring, lending, medical, or legal outcomes)?",
      "type": "select",
      "options": ["AI is used with no required human review", "Human can override but review is optional", "Human review is required before any action is taken", "AI is advisory only — humans make all final decisions", "No AI use or no human oversight controls are documented for high-stakes decisions"],
      "na_option": "No AI use or no human oversight controls are documented for high-stakes decisions",
      "weight": 1.5,
      "nist_control_id": "GOVERN 4.1"
    },
    {
      "id": "at_005",
      "domain": "ai_trustworthiness",
      "text": "Has your organization identified and documented all groups of people who could be impacted — positively or negatively — by your AI systems?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "MAP 5.2"
    },
    {
      "id": "at_006",
      "domain": "ai_trustworthiness",
      "text": "Does your organization engage external parties — customers, auditors, or independent researchers — to evaluate AI system performance and fairness?",
      "type": "boolean",
      "weight": 1.0,
      "nist_control_id": "MEASURE 1.3"
    },
    {
      "id": "at_007",
      "domain": "ai_trustworthiness",
      "text": "How would you rate the degree to which your AI systems provide interpretable outputs — i.e., users can understand why a result was produced?",
      "type": "scale",
      "weight": 1.1,
      "nist_control_id": "MEASURE 2.6"
    },
    {
      "id": "at_008",
      "domain": "ai_trustworthiness",
      "text": "How frequently does your organization formally re-evaluate AI systems after initial deployment to check for performance drift or emergent risks?",
      "type": "select",
      "options": ["Never re-evaluated after deployment", "Only re-evaluated if a problem occurs", "Annual formal review scheduled", "Quarterly formal review scheduled", "Continuous monitoring with regular formal reviews"],
      "weight": 1.2,
      "nist_control_id": "MEASURE 3.1"
    },
    {
      "id": "ir_001",
      "domain": "infra_readiness",
      "text": "Is multi-factor authentication (MFA) enforced for access to all AI tools and services?",
      "type": "boolean",
      "weight": 1.5,
      "nist_control_id": "GOVERN 3.1"
    },
    {
      "id": "ir_002",
      "domain": "infra_readiness",
      "text": "Does your organization use a password manager or privileged access management (PAM) system to control AI platform credentials?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "MANAGE 3.1"
    },
    {
      "id": "ir_003",
      "domain": "infra_readiness",
      "text": "Are AI service integrations (APIs, webhooks, data pipelines) protected by transport-layer encryption (TLS 1.2 or higher)?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "MANAGE 4.1"
    },
    {
      "id": "ir_004",
      "domain": "infra_readiness",
      "text": "Does your organization maintain network segmentation or access boundaries that isolate AI workloads from general corporate systems?",
      "type": "boolean",
      "weight": 1.0,
      "nist_control_id": "MANAGE 4.1"
    },
    {
      "id": "ir_005",
      "domain": "infra_readiness",
      "text": "How would you rate your organization''s incident response readiness for an AI-related data exposure or system failure event?",
      "type": "scale",
      "weight": 1.2,
      "nist_control_id": "MANAGE 1.3"
    },
    {
      "id": "ir_006",
      "domain": "infra_readiness",
      "text": "Does your organization have a documented procedure to quickly shut down, roll back, or disable an AI system if it produces harmful or incorrect outputs?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "MANAGE 3.2"
    },
    {
      "id": "ir_007",
      "domain": "infra_readiness",
      "text": "Are AI systems continuously monitored in production for performance degradation, anomalous outputs, or unexpected behavior?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "MEASURE 3.1"
    },
    {
      "id": "ca_001",
      "domain": "compliance_awareness",
      "text": "Has your organization identified which AI use cases may trigger regulatory requirements (HIPAA, FFIEC, CMMC, state AI laws, EU AI Act, etc.)?",
      "type": "boolean",
      "weight": 1.5,
      "nist_control_id": "MAP 5.1"
    },
    {
      "id": "ca_002",
      "domain": "compliance_awareness",
      "text": "Does your organization maintain executed vendor agreements (BAAs, DPAs) with AI providers that process sensitive or regulated data?",
      "type": "boolean",
      "weight": 1.4,
      "nist_control_id": "GOVERN 5.1"
    },
    {
      "id": "ca_003",
      "domain": "compliance_awareness",
      "text": "Has your organization conducted a formal risk assessment specifically addressing AI adoption, deployment, and associated data flows?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "MAP 5.2"
    },
    {
      "id": "ca_004",
      "domain": "compliance_awareness",
      "text": "Does your organization have a formal compliance program with policies, controls, and monitoring that explicitly address AI risks?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "MAP 5.1"
    },
    {
      "id": "ca_005",
      "domain": "compliance_awareness",
      "text": "How would you rate your compliance team''s understanding of AI-specific regulatory requirements relevant to your industry?",
      "type": "scale",
      "weight": 1.0,
      "nist_control_id": "GOVERN 1.7"
    },
    {
      "id": "ca_006",
      "domain": "compliance_awareness",
      "text": "Does your organization have a documented AI ethics or responsible AI use framework that guides how AI is developed and deployed?",
      "type": "boolean",
      "weight": 0.9,
      "nist_control_id": "GOVERN 4.2"
    },
    {
      "id": "ca_007",
      "domain": "compliance_awareness",
      "text": "Does your organization have a documented incident response procedure specifically for AI-related events (data leakage via AI, biased outputs, AI system failure)?",
      "type": "boolean",
      "weight": 1.3,
      "nist_control_id": "MANAGE 1.2"
    },
    {
      "id": "ca_008",
      "domain": "compliance_awareness",
      "text": "Are documented risk treatment plans in place for high-priority AI risks identified through your risk assessment process?",
      "type": "boolean",
      "weight": 1.2,
      "nist_control_id": "MANAGE 1.2"
    },
    {
      "id": "ca_009",
      "domain": "compliance_awareness",
      "text": "Does your organization assess and manage risks from AI components or models sourced from third parties, open-source repositories, or AI supply chains?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "MAP 4.2"
    },
    {
      "id": "ap_001",
      "domain": "automation_potential",
      "text": "Does your organization have standardized, repeatable workflows that could benefit from AI automation?",
      "type": "boolean",
      "weight": 1.0,
      "nist_control_id": "MAP 4.1"
    },
    {
      "id": "ap_002",
      "domain": "automation_potential",
      "text": "Are there documented manual review processes where AI assistance could reduce risk, error rate, or processing time?",
      "type": "boolean",
      "weight": 1.0,
      "nist_control_id": "MANAGE 2.2"
    },
    {
      "id": "ap_003",
      "domain": "automation_potential",
      "text": "Does your organization have a formal process for evaluating new AI capabilities before adoption — including risk, cost, and compliance review?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "MAP 3.1"
    },
    {
      "id": "ap_004",
      "domain": "automation_potential",
      "text": "How would you rate your organization''s technical infrastructure readiness to support secure AI automation at scale?",
      "type": "scale",
      "weight": 1.0,
      "nist_control_id": "MANAGE 4.1"
    },
    {
      "id": "ap_005",
      "domain": "automation_potential",
      "text": "Does your organization have active executive buy-in and dedicated budget allocated for responsible AI investment and governance?",
      "type": "boolean",
      "weight": 1.1,
      "nist_control_id": "GOVERN 3.2"
    }
  ]'::jsonb
)
ON CONFLICT (schema_version) DO UPDATE SET
  is_current = TRUE,
  questions   = EXCLUDED.questions;

-- ─── Retire v1.0 prompt templates ────────────────────────────────────────────
UPDATE prompt_versions SET is_active = FALSE WHERE version = 'v1.0';

-- ─── Prompt templates v2.0 ───────────────────────────────────────────────────

INSERT INTO prompt_versions (prompt_key, version, is_active, system_prompt, user_prompt_template)
VALUES
(
  'executive_report',
  'v2.0',
  TRUE,
  'You are a senior AI governance advisor conducting an evidence-based NIST AI RMF gap assessment. Your audience is C-suite executives and board members who will share this report with auditors, insurers, and regulators.

Tone: authoritative, specific, and direct. Never use generic advice. Every finding must reference specific control gaps. Every roadmap item must name exact tools, vendors, estimated costs, and an owner role.

Rules:
- Never say "certified" — use "aligned with" or "designed to support compliance with"
- Never say "consider implementing" — say exactly what to implement and who makes it happen
- Reference NIST AI RMF control IDs (e.g., GOVERN 1.1, MAP 3.1) in findings where relevant
- Risk dollar figures must be grounded in industry benchmarks (IBM Cost of Data Breach, HHS fine schedules, etc.)
- Return a single valid JSON object — no markdown, no preamble, just the JSON',

  'Generate an executive AI governance advisory report for the following organization.

Organization: {{org_name}}
Industry: {{industry}}
Profile Type: {{profile_type}}
Overall AI Governance Risk Score: {{overall_score}}/100 ({{risk_band}} risk)

Domain Scores:
{{domain_scores}}

NIST AI RMF Control Coverage (computed from assessment responses):
{{nist_coverage}}

Using the NIST control coverage above, write findings that cite specific gaps by control ID. For roadmap items, name the exact tool or vendor, estimated cost range, and who owns execution (IT, Legal, HR, or Exec).

Respond with ONLY a valid JSON object in this exact structure:
{
  "executive_summary": "Three paragraphs: (1) overall AI governance posture and headline risk rating with business context, (2) the two or three most critical control failures and their specific business or regulatory consequences, (3) the single highest-priority action and the ROI of addressing it within 30 days",
  "key_strengths": ["specific strength with evidence from the assessment", "strength 2", "strength 3"],
  "critical_gaps": ["gap referencing a specific NIST control ID and business impact", "gap 2", "gap 3", "gap 4", "gap 5"],
  "domain_findings": {
    "data_governance": "2-3 sentences citing specific data classification, lineage, or AI inventory gaps",
    "security_posture": "2-3 sentences on access control, testing, and monitoring gaps",
    "ai_maturity": "2-3 sentences on policy, accountability, and governance culture gaps",
    "ai_trustworthiness": "2-3 sentences on bias evaluation, explainability, privacy impact, and human oversight gaps — these are the gaps regulators scrutinize most",
    "infra_readiness": "2-3 sentences on MFA, encryption, monitoring, and incident response gaps",
    "compliance_awareness": "2-3 sentences on regulatory identification, vendor agreements, and risk treatment gaps",
    "automation_potential": "2-3 sentences on the AI readiness opportunity and what is blocking safe scaling"
  },
  "nist_function_findings": {
    "GOVERN": "2-3 sentences on the most significant policies, accountability, and organizational culture gaps under the GOVERN function",
    "MAP": "2-3 sentences on risk context, AI system categorization, and stakeholder impact gaps under the MAP function",
    "MEASURE": "2-3 sentences on the most critical testing, evaluation, bias detection, and monitoring gaps under the MEASURE function",
    "MANAGE": "2-3 sentences on risk response planning, incident handling, and treatment plan gaps under the MANAGE function"
  },
  "risk_quantification": {
    "estimated_breach_cost": "Dollar range based on industry benchmarks — e.g. $X–$Y for a mid-size healthcare org per IBM 2024 Cost of Data Breach",
    "regulatory_exposure": "Specific fine exposure — e.g. HIPAA Tier 2 at $1,000–$50,000 per violation if PHI is involved",
    "insurance_impact": "One sentence on how the identified gaps affect cyber liability premium or coverage eligibility"
  },
  "roadmap": {
    "days_30": [
      {
        "title": "Action title — specific and imperative",
        "description": "Exact steps. Name the tool or vendor. Example: Enable MFA in Microsoft Entra ID for the 12 users currently without it — Settings > Security > MFA > Enforce for all users. Estimated 2 hours of IT time.",
        "effort": "Low",
        "impact": "High",
        "estimated_cost": "$0 (included in M365 license)",
        "owner": "IT"
      }
    ],
    "days_60": [
      {
        "title": "Action title",
        "description": "Exact steps with tool/vendor names and implementation guidance",
        "effort": "Medium",
        "impact": "High",
        "estimated_cost": "$X–$Y",
        "owner": "IT|Legal|HR|Exec"
      }
    ],
    "days_90": [
      {
        "title": "Action title",
        "description": "Exact steps with tool/vendor names and implementation guidance",
        "effort": "High",
        "impact": "High",
        "estimated_cost": "$X–$Y",
        "owner": "IT|Legal|HR|Exec"
      }
    ]
  },
  "framework_alignments": [
    {"framework": "NIST AI RMF", "alignment_pct": 0, "gap_count": 0, "notes": "Name the 2-3 specific NIST functions with the most gaps"},
    {"framework": "SOC 2 Type II", "alignment_pct": 0, "gap_count": 0, "notes": "Specific criteria gaps relevant to this org"},
    {"framework": "HIPAA", "alignment_pct": 0, "gap_count": 0, "notes": "Include only if industry is healthcare or org handles PHI"}
  ],
  "disclaimer": "This report reflects alignment with, not certification to, referenced frameworks. It is intended as an advisory tool to support internal risk management decisions and does not constitute legal or regulatory advice. FrostGate AI Governance Assessment."
}'
),
(
  'technical_report',
  'v2.0',
  TRUE,
  'You are an AI governance advisor generating a technical advisory report for a CISO or CTO. Your audience understands security architecture and controls. Be precise about control failures, attack surfaces, and implementation steps. Reference specific NIST AI RMF control IDs, CVE classes, and OWASP AI Security risks where relevant. Never say "certified". Return a single valid JSON object.',

  'Generate a technical AI governance advisory report for the following organization.

Organization: {{org_name}}
Industry: {{industry}}
Profile Type: {{profile_type}}
Overall AI Governance Risk Score: {{overall_score}}/100 ({{risk_band}} risk)

Domain Scores:
{{domain_scores}}

NIST AI RMF Control Coverage:
{{nist_coverage}}

Generate the report with technical depth — specific control names, NIST AI RMF control IDs, OWASP LLM Top 10 risks where applicable, and implementation steps with tooling recommendations (e.g., HashiCorp Vault for secrets, Presidio for PII detection, Prometheus for monitoring).

Respond with ONLY a valid JSON object using the same schema as the executive report but with technical depth in all narrative fields. Include estimated_cost and owner in all roadmap items.'
),
(
  'compliance_report',
  'v2.0',
  TRUE,
  'You are an AI governance advisor generating a compliance-oriented advisory report for a CCO, legal counsel, or external auditor. Use audit artifact language. Cite specific regulatory provisions, framework control IDs, and evidence requirements. Never say "certified" or "compliant" — use "aligned with" or "designed to support compliance with". Return a single valid JSON object.',

  'Generate a compliance-focused AI governance advisory report for the following organization.

Organization: {{org_name}}
Industry: {{industry}}
Profile Type: {{profile_type}}
Overall AI Governance Risk Score: {{overall_score}}/100 ({{risk_band}} risk)

Domain Scores:
{{domain_scores}}

NIST AI RMF Control Coverage:
{{nist_coverage}}

Generate the report with compliance depth — cite specific NIST AI RMF control IDs, regulatory provisions (HIPAA §164.308, CMMC AC.1.001, etc.), evidence requirements for each gap, and audit readiness status. Every roadmap item must include the regulatory obligation it satisfies and the evidence artifact it produces.

Respond with ONLY a valid JSON object using the same schema as the executive report but with compliance depth in all narrative fields. Include estimated_cost and owner in all roadmap items.'
)
ON CONFLICT (prompt_key, version) DO UPDATE SET
  is_active            = TRUE,
  system_prompt        = EXCLUDED.system_prompt,
  user_prompt_template = EXCLUDED.user_prompt_template;
