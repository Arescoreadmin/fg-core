/**
 * interviewGuides.ts — sector-specific interview guide data.
 *
 * Owns all InterviewGuide definitions and exports a resolver that returns the
 * correct guide for a given role + assessment type combination. The component
 * (InterviewForm.tsx) imports only the types and the resolver — no guide data
 * lives in the component itself.
 *
 * Sector resolution: assessment_type → SectorKey → guide lookup.
 * Falls back to DEFAULT_GUIDES when no sector-specific override exists.
 *
 * NOT STANDALONE — this module is part of the fg-core field assessment
 * subsystem and has no meaning outside of it.
 */

import type { ObservationDomain } from '@/lib/fieldAssessmentApi';

export type SectorKey = 'default' | 'healthcare' | 'pci_dss' | 'dora' | 'government';

export interface InterviewQuestion {
  text: string;
  nist: string[];   // NIST AI RMF 1.0 subcategory refs
  regs?: string[];  // Sector-specific regulatory refs
}

export interface InterviewGuide {
  roleLabel: string;
  domain: ObservationDomain;
  suggestedTitle: string;
  topics: string[];
  questions: InterviewQuestion[];
}

// Maps engagement assessment_type → sector key
export const ASSESSMENT_TYPE_TO_SECTOR: Record<string, SectorKey> = {
  hipaa: 'healthcare',
  pci_dss: 'pci_dss',
  dora: 'dora',
  cmmc: 'government',
  fedramp: 'government',
  nist_800_171: 'government',
  // ai_governance, comprehensive, soc2, iso27001 → 'default' (not listed → fallback)
};

// ── Default guides (all 15 roles) ────────────────────────────────────────────

export const DEFAULT_GUIDES: Record<string, InterviewGuide> = {
  // ── Playbook-required roles ────────────────────────────────────────────────
  executive_sponsor: {
    roleLabel: 'Executive Sponsor',
    domain: 'ai_governance',
    suggestedTitle: 'Executive Sponsor — AI governance awareness interview',
    topics: ['AI strategy and board-level oversight', 'Risk appetite and tolerance', 'Policy awareness and approval', 'AI investment and roadmap', 'Incident escalation path'],
    questions: [
      { text: 'What AI tools or systems does your organisation currently use or plan to adopt?', nist: ['GOVERN 1.1', 'MAP 1.1'] },
      { text: 'Who owns AI risk in your organisation — is there a named role, committee, or policy owner?', nist: ['GOVERN 1.2', 'GOVERN 5.1'] },
      { text: 'Are you aware of the current AI usage policy? Have you reviewed or formally approved it?', nist: ['GOVERN 1.1', 'GOVERN 1.3'] },
      { text: 'How do you receive updates on AI-related risks, incidents, or compliance obligations?', nist: ['GOVERN 1.6', 'GOVERN 6.1'] },
      { text: 'What level of AI risk is acceptable to the business, and how was that threshold set?', nist: ['GOVERN 2.1', 'GOVERN 2.2'] },
      { text: 'Is AI adoption factored into your strategic roadmap or board / leadership reporting?', nist: ['GOVERN 1.5', 'MAP 1.5'] },
      { text: 'Have there been any AI-related incidents or near-misses in the last 12 months?', nist: ['MANAGE 2.4', 'MAP 3.5'] },
      { text: 'What approval or oversight process exists before a new AI tool is deployed?', nist: ['GOVERN 1.1', 'GOVERN 4.1'] },
    ],
  },
  ai_system_owner: {
    roleLabel: 'AI System Owner',
    domain: 'ai_governance',
    suggestedTitle: 'AI System Owner — system scope, data use, and monitoring interview',
    topics: ['System purpose and intended use', 'Training and inference data', 'Known failure modes and limitations', 'Production monitoring', 'Change and incident management'],
    questions: [
      { text: 'What AI systems are you responsible for — what is their intended purpose and scope of use?', nist: ['MAP 1.1', 'GOVERN 1.2'] },
      { text: 'What data does the system use as input, and where does that data come from?', nist: ['MAP 1.5', 'MEASURE 2.5'] },
      { text: 'What are the known failure modes, edge cases, or limitations of the system?', nist: ['MAP 5.1', 'MEASURE 2.7'] },
      { text: 'How is the system monitored in production — are there performance or quality thresholds?', nist: ['MANAGE 2.2', 'MEASURE 4.1'] },
      { text: 'How are changes to the model or system tested and approved before deployment?', nist: ['MANAGE 1.1', 'GOVERN 1.7'] },
      { text: 'What training or guidance do end users receive about appropriate use of the system?', nist: ['GOVERN 1.6', 'MAP 1.6'] },
      { text: 'If the system produced a harmful or incorrect output, what is the escalation path?', nist: ['MANAGE 2.4', 'GOVERN 1.2'] },
    ],
  },
  security_owner: {
    roleLabel: 'Security Owner',
    domain: 'ai_governance',
    suggestedTitle: 'Security Owner — AI security controls and risk posture interview',
    topics: ['AI risk register and classification', 'Technical security controls', 'Logging and audit trail', 'Vendor and third-party risk', 'Incident response'],
    questions: [
      { text: 'Are AI systems formally listed in the risk register? At what severity are they classified?', nist: ['GOVERN 1.1', 'MAP 5.1'] },
      { text: 'What technical controls restrict what data AI systems can access or process?', nist: ['MANAGE 1.1', 'MEASURE 2.7'] },
      { text: 'Is access to AI tools and their outputs logged, reviewed, and retained?', nist: ['MEASURE 4.1', 'MANAGE 2.2'] },
      { text: 'How are third-party AI vendors assessed for security risk before and after onboarding?', nist: ['GOVERN 4.1', 'MANAGE 3.1'] },
      { text: 'Has penetration testing or red-teaming been conducted specifically for AI systems?', nist: ['MEASURE 2.7', 'MANAGE 1.3'] },
      { text: 'What is the incident response process if an AI system is compromised or produces harmful output?', nist: ['MANAGE 2.4', 'GOVERN 6.2'] },
      { text: 'How do you detect and respond to unsanctioned or shadow AI tool usage?', nist: ['MAP 3.5', 'GOVERN 4.2'] },
    ],
  },
  legal_or_compliance: {
    roleLabel: 'Legal / Compliance',
    domain: 'compliance',
    suggestedTitle: 'Legal & Compliance — regulatory obligations and legal exposure interview',
    topics: ['Applicable AI regulations and frameworks', 'Legal review of AI deployments', 'Contractual AI obligations', 'Regulatory incident reporting', 'Intellectual property and liability'],
    questions: [
      { text: 'Which regulations or frameworks apply to your AI use (EU AI Act, NIST AI RMF, ISO 42001, sector-specific)?', nist: ['GOVERN 1.1', 'MAP 5.2'] },
      { text: 'Is legal review required before deploying a new AI system — what does that process look like?', nist: ['GOVERN 1.1', 'GOVERN 4.1'] },
      { text: 'Do vendor contracts include AI-specific clauses covering data use, training, and auditability?', nist: ['GOVERN 4.1', 'MANAGE 3.1'] },
      { text: 'What is the legal obligation to report an AI-related incident to a regulator or affected party?', nist: ['MANAGE 2.4', 'GOVERN 6.1'] },
      { text: 'How is personal data handled when used in AI systems — is there a legal basis for each use?', nist: ['MEASURE 2.5', 'GOVERN 1.1'] },
      { text: 'Has legal reviewed IP ownership, liability, and indemnity exposure for AI-generated outputs?', nist: ['MAP 5.1', 'GOVERN 1.1'] },
      { text: 'How do you track regulatory changes (EU AI Act phases, sector guidance) and translate them into policy updates?', nist: ['GOVERN 1.7', 'MAP 5.2'] },
    ],
  },
  compliance_owner: {
    roleLabel: 'Compliance Owner',
    domain: 'compliance',
    suggestedTitle: 'Compliance Owner — AI compliance programme and audit readiness interview',
    topics: ['Compliance register for AI systems', 'Policy review cycle and ownership', 'Training and certification obligations', 'Audit readiness', 'Control testing and evidence'],
    questions: [
      { text: 'Is there a compliance register that maps AI systems to applicable regulations and controls?', nist: ['GOVERN 1.1', 'MAP 5.2'] },
      { text: 'How often are AI-related policies reviewed, who owns them, and what triggers an out-of-cycle review?', nist: ['GOVERN 1.1', 'GOVERN 1.3'] },
      { text: 'Are there mandatory training or certification requirements for staff who deploy or operate AI systems?', nist: ['GOVERN 1.6', 'MAP 5.2'] },
      { text: 'How would you demonstrate AI compliance readiness to an external auditor today?', nist: ['GOVERN 5.1', 'MEASURE 4.1'] },
      { text: 'How are AI-specific controls tested, and how frequently?', nist: ['MEASURE 2.7', 'MANAGE 1.3'] },
      { text: 'How do you track regulatory changes and translate them into updated controls or policies?', nist: ['GOVERN 1.7', 'MAP 5.2'] },
    ],
  },
  system_owner: {
    roleLabel: 'System Owner',
    domain: 'operational_security',
    suggestedTitle: 'System Owner — system configuration, access, and continuity interview',
    topics: ['System purpose and data dependencies', 'User access and role management', 'Change and release management', 'Performance and quality monitoring', 'Business continuity'],
    questions: [
      { text: 'What is the primary purpose of the system and what business process does it support?', nist: ['MAP 1.1', 'GOVERN 1.2'] },
      { text: 'What data does the system depend on, and how is sensitive data protected within it?', nist: ['MAP 1.5', 'MEASURE 2.5'] },
      { text: 'How is user access to the system granted, reviewed, and revoked?', nist: ['GOVERN 4.1', 'MANAGE 2.2'] },
      { text: 'What is the change management process — how are releases tested and approved?', nist: ['GOVERN 1.7', 'MANAGE 1.1'] },
      { text: 'How is system performance monitored — are there SLAs or quality thresholds in place?', nist: ['MEASURE 4.1', 'MANAGE 2.2'] },
      { text: 'What is the business continuity and disaster recovery plan for this system?', nist: ['MANAGE 2.4', 'GOVERN 6.2'] },
      { text: 'Are there third-party integrations — how are those dependencies and risks managed?', nist: ['GOVERN 4.1', 'MANAGE 3.1'] },
    ],
  },
  privacy_officer: {
    roleLabel: 'Privacy Officer',
    domain: 'data_security',
    suggestedTitle: 'Privacy Officer — AI data use, consent, and data subject rights interview',
    topics: ['Personal data in AI systems', 'Legal basis and consent', 'Data subject rights', 'Data minimisation and retention', 'DPIA and bias assessment'],
    questions: [
      { text: 'Which AI systems process personal data, and what categories of data are involved?', nist: ['MEASURE 2.5', 'GOVERN 1.1'] },
      { text: 'What is the legal basis for using personal data in each AI system?', nist: ['MEASURE 2.5', 'MAP 1.5'] },
      { text: 'How are data subject rights (access, erasure, portability) handled for data used in AI?', nist: ['MEASURE 2.5', 'GOVERN 1.7'] },
      { text: 'How is data minimisation applied — is only the minimum necessary data used by AI systems?', nist: ['MEASURE 2.5', 'MAP 1.5'] },
      { text: 'Are there cross-border data transfers involved in AI processing, and how are they governed?', nist: ['GOVERN 4.1', 'MEASURE 2.5'] },
      { text: 'Has a DPIA (Data Protection Impact Assessment) been completed for high-risk AI systems?', nist: ['MAP 5.1', 'MEASURE 2.5'] },
      { text: 'Has the system been assessed for bias or discriminatory outputs affecting protected characteristics?', nist: ['MAP 5.1', 'MEASURE 2.7'] },
    ],
  },

  // ── Additional roles for broader playbook coverage ─────────────────────────
  ciso: {
    roleLabel: 'CISO',
    domain: 'ai_governance',
    suggestedTitle: 'CISO — AI security posture and governance interview',
    topics: ['AI security controls and risk framework', 'Data classification for AI inputs/outputs', 'Vendor and third-party AI risk', 'Incident response for AI events', 'Monitoring and detection capability'],
    questions: [
      { text: 'Which AI tools or platforms are in scope for your security programme?', nist: ['GOVERN 1.1', 'MAP 1.1'] },
      { text: "How are AI vendors assessed before onboarding — what's the security review process?", nist: ['GOVERN 4.1', 'MANAGE 3.1'] },
      { text: 'How is sensitive data classified and protected when used as AI input?', nist: ['MEASURE 2.5', 'MAP 1.5'] },
      { text: 'Is there a defined incident response playbook for AI-specific events (model poisoning, data exfiltration via AI)?', nist: ['MANAGE 2.4', 'GOVERN 6.2'] },
      { text: 'What monitoring or alerting is in place for anomalous AI usage or outputs?', nist: ['MEASURE 4.1', 'MANAGE 2.2'] },
      { text: 'Have any AI tools been shadow-deployed without security review?', nist: ['MAP 3.5', 'GOVERN 4.2'] },
      { text: 'How does your team keep pace with the emerging AI threat landscape and regulatory changes?', nist: ['GOVERN 1.7', 'MAP 5.2'] },
    ],
  },
  security_officer: {
    roleLabel: 'Security Officer',
    domain: 'ai_governance',
    suggestedTitle: 'Security Officer — AI risk and control interview',
    topics: ['Control implementation', 'Risk register entries for AI', 'Monitoring and detection', 'Policy enforcement'],
    questions: [
      { text: 'Are AI systems listed in the risk register? At what severity?', nist: ['GOVERN 1.1', 'MAP 5.1'] },
      { text: 'What technical controls limit what data AI tools can access?', nist: ['MANAGE 1.1', 'MEASURE 2.7'] },
      { text: 'Is access to AI tools logged and reviewed?', nist: ['MEASURE 4.1', 'MANAGE 2.2'] },
      { text: 'How are policy violations around AI use identified and handled?', nist: ['MAP 3.5', 'GOVERN 1.1'] },
      { text: 'Are AI-specific risks included in periodic security reviews?', nist: ['MEASURE 2.7', 'MANAGE 1.3'] },
    ],
  },
  data_steward: {
    roleLabel: 'Data Steward',
    domain: 'data_security',
    suggestedTitle: 'Data Steward — data governance and AI data use interview',
    topics: ['Data classification and lineage', 'AI training and inference data', 'Consent and data subject rights', 'Retention and deletion', 'Cross-border data flows'],
    questions: [
      { text: 'Which data sets are used as input to AI models or third-party AI services?', nist: ['MAP 1.5', 'GOVERN 1.1'] },
      { text: 'How is personal or sensitive data identified before it reaches an AI system?', nist: ['MEASURE 2.5', 'MAP 1.5'] },
      { text: "Is there a process to ensure AI outputs don't expose regulated data (PII, health, financial)?", nist: ['MEASURE 2.5', 'MANAGE 2.2'] },
      { text: 'How are data subject rights (access, erasure) handled for data used in AI training?', nist: ['MEASURE 2.5', 'GOVERN 1.7'] },
      { text: 'Are there retention policies specific to AI-generated outputs or logs?', nist: ['GOVERN 1.7', 'MAP 1.5'] },
      { text: 'Do any AI vendors process data outside the primary jurisdiction? Is this documented?', nist: ['GOVERN 4.1', 'MEASURE 2.5'] },
    ],
  },
  it_admin: {
    roleLabel: 'IT Administrator',
    domain: 'access_management',
    suggestedTitle: 'IT Admin — access control and AI tool provisioning interview',
    topics: ['AI tool provisioning and deprovisioning', 'Access control and least privilege', 'Shadow IT / unsanctioned AI', 'Endpoint controls', 'Patch and update management'],
    questions: [
      { text: 'What is the process for provisioning a user with access to an approved AI tool?', nist: ['GOVERN 4.1', 'MANAGE 2.2'] },
      { text: 'Are AI service accounts or API keys managed in a secrets manager or inventory?', nist: ['MANAGE 2.2', 'MEASURE 4.1'] },
      { text: 'How do you identify and block unsanctioned AI tool usage on corporate devices?', nist: ['MAP 3.5', 'GOVERN 4.2'] },
      { text: 'Is MFA enforced for access to AI platforms?', nist: ['MANAGE 1.1', 'GOVERN 4.1'] },
      { text: 'How are AI tool updates or patches applied — is there a tested rollout process?', nist: ['MANAGE 1.1', 'GOVERN 1.7'] },
      { text: 'When an employee leaves, how quickly is their AI tool access revoked?', nist: ['GOVERN 4.1', 'MANAGE 2.2'] },
    ],
  },
  compliance_officer: {
    roleLabel: 'Compliance Officer',
    domain: 'compliance',
    suggestedTitle: 'Compliance Officer — regulatory obligations and AI compliance interview',
    topics: ['Applicable AI regulations and frameworks', 'Audit readiness', 'Policy review cycle', 'Training and awareness obligations', 'Incident reporting requirements'],
    questions: [
      { text: 'Which regulations or frameworks govern AI use in your organisation (EU AI Act, NIST AI RMF, ISO 42001, sector-specific)?', nist: ['GOVERN 1.1', 'MAP 5.2'] },
      { text: 'Has a formal AI risk classification been completed against applicable regulation?', nist: ['MAP 5.1', 'MEASURE 2.7'] },
      { text: 'How often are AI-related policies reviewed, and who signs off?', nist: ['GOVERN 1.1', 'GOVERN 1.3'] },
      { text: 'Are there mandatory training or certification requirements for staff deploying or using AI?', nist: ['GOVERN 1.6', 'MAP 5.2'] },
      { text: 'What is the reporting obligation if an AI system causes a material incident or harm?', nist: ['MANAGE 2.4', 'GOVERN 6.1'] },
      { text: 'Is there a register of AI systems mapped to their regulatory risk category?', nist: ['GOVERN 1.1', 'MAP 5.2'] },
    ],
  },
  department_head: {
    roleLabel: 'Department Head',
    domain: 'ai_governance',
    suggestedTitle: 'Department Head — operational AI use and awareness interview',
    topics: ['Day-to-day AI tool usage', 'Policy awareness within the team', 'Data handling practices', 'Risk awareness', 'Informal / shadow AI adoption'],
    questions: [
      { text: 'Which AI tools does your team use on a regular basis — sanctioned or otherwise?', nist: ['MAP 3.5', 'GOVERN 1.1'] },
      { text: 'Are your team members aware of the AI usage policy and any restrictions?', nist: ['GOVERN 1.6', 'GOVERN 1.1'] },
      { text: 'Has your team used AI to process or summarise sensitive business or customer data?', nist: ['MEASURE 2.5', 'MAP 1.5'] },
      { text: 'Have you seen team members use personal AI accounts (e.g. free ChatGPT) for work tasks?', nist: ['MAP 3.5', 'GOVERN 4.2'] },
      { text: 'How do team members raise concerns if they think an AI output is wrong or harmful?', nist: ['MANAGE 2.4', 'GOVERN 6.1'] },
      { text: 'Has AI changed how work gets done in your team — are those changes documented?', nist: ['MAP 1.6', 'GOVERN 1.1'] },
    ],
  },
  vendor_manager: {
    roleLabel: 'Vendor / Procurement Manager',
    domain: 'vendor_management',
    suggestedTitle: 'Vendor Manager — third-party AI risk and procurement interview',
    topics: ['Vendor AI due diligence', 'Contractual AI obligations', 'Sub-processor visibility', 'Ongoing vendor monitoring', 'Exit and contingency planning'],
    questions: [
      { text: 'What due diligence is performed on vendors that use or offer AI capabilities?', nist: ['GOVERN 4.1', 'MANAGE 3.1'] },
      { text: 'Are AI-specific clauses included in vendor contracts (data use, model training, auditability)?', nist: ['GOVERN 4.1', 'MANAGE 3.1'] },
      { text: 'Do vendor agreements require disclosure if an AI tool changes significantly or a new AI capability is added?', nist: ['GOVERN 4.2', 'MANAGE 3.1'] },
      { text: 'How are vendor sub-processors assessed — especially for AI data handling?', nist: ['GOVERN 4.1', 'MEASURE 2.5'] },
      { text: 'Is there a periodic review of active AI vendor relationships and their risk posture?', nist: ['MANAGE 3.1', 'GOVERN 4.2'] },
      { text: 'What is the exit strategy if a key AI vendor becomes non-compliant or ceases operation?', nist: ['GOVERN 6.2', 'MANAGE 3.1'] },
    ],
  },
  incident_response_lead: {
    roleLabel: 'Incident Response Lead',
    domain: 'incident_response',
    suggestedTitle: 'Incident Response Lead — AI incident preparedness interview',
    topics: ['AI incident definition and classification', 'Detection and triage', 'Playbook coverage', 'Post-incident review', 'Lessons learned and policy update'],
    questions: [
      { text: 'How does your organisation define an AI-related incident — what triggers a response?', nist: ['MANAGE 2.4', 'GOVERN 1.1'] },
      { text: 'Is there a dedicated playbook or runbook for AI incidents, separate from general IR?', nist: ['MANAGE 2.4', 'GOVERN 6.2'] },
      { text: 'How would an AI data exfiltration or model manipulation event be detected?', nist: ['MEASURE 4.1', 'MANAGE 2.4'] },
      { text: 'Who is the escalation path for an AI incident — is the CISO or legal involved at what threshold?', nist: ['GOVERN 1.2', 'MANAGE 2.4'] },
      { text: 'Have any AI incidents or near-misses occurred? Were they formally reviewed?', nist: ['MAP 3.5', 'MANAGE 2.4'] },
      { text: 'After an AI incident, how are lessons learned fed back into policy or controls?', nist: ['GOVERN 1.7', 'MANAGE 1.3'] },
    ],
  },
};

// ── Sector-specific overrides ─────────────────────────────────────────────────
// Only the roles that need different questions per sector. Each entry fully
// replaces the default guide for that role+sector combination.

export const SECTOR_GUIDES: Partial<Record<SectorKey, Partial<Record<string, InterviewGuide>>>> = {

  // ── Healthcare (HIPAA / HITECH / FDA SaMD) ────────────────────────────────
  healthcare: {
    executive_sponsor: {
      roleLabel: 'Executive Sponsor',
      domain: 'ai_governance',
      suggestedTitle: 'Executive Sponsor — HIPAA AI governance and PHI risk interview',
      topics: [
        'AI strategy involving PHI or clinical data',
        'Board-level HIPAA accountability and AI risk appetite',
        'Business Associate Agreement oversight',
        'Clinical decision support governance',
        'Regulatory and liability exposure from AI in care pathways',
      ],
      questions: [
        {
          text: 'Which AI systems does your organisation operate that touch Protected Health Information (PHI) — directly or as part of a clinical workflow?',
          nist: ['GOVERN 1.1', 'MAP 1.1'],
          regs: ['HIPAA §164.308', 'HIPAA §164.502'],
        },
        {
          text: 'Have Business Associate Agreements (BAAs) been executed with every AI vendor that receives, processes, or stores PHI on your behalf?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['HIPAA §164.308(b)', 'HITECH §13401'],
        },
        {
          text: 'How is AI risk — particularly for clinical decision support tools — reported to the board or executive leadership, and how often?',
          nist: ['GOVERN 1.6', 'GOVERN 6.1'],
          regs: ['HIPAA §164.308(a)(1)', 'FDA SaMD'],
        },
        {
          text: 'What is your organisation\'s risk appetite for deploying AI in patient-facing or safety-critical clinical contexts?',
          nist: ['GOVERN 2.1', 'GOVERN 2.2'],
          regs: ['FDA SaMD', 'HIPAA §164.308(a)(1)'],
        },
        {
          text: 'Has your organisation completed or commissioned a HIPAA Security Risk Analysis that specifically addresses AI systems processing ePHI?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['HIPAA §164.308(a)(1)(ii)(A)', 'HITECH §13401'],
        },
        {
          text: 'Are there documented procedures for reporting a PHI breach caused by or involving an AI system — including notifying HHS and affected patients?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['HIPAA §164.502', 'HITECH §13401'],
        },
        {
          text: 'How does leadership ensure that AI tools used by clinical staff comply with the HIPAA minimum necessary standard for PHI access?',
          nist: ['GOVERN 1.3', 'MEASURE 2.5'],
          regs: ['HIPAA §164.502(b)', 'HIPAA §164.312'],
        },
      ],
    },
    security_owner: {
      roleLabel: 'Security Owner',
      domain: 'ai_governance',
      suggestedTitle: 'Security Owner — HIPAA AI technical safeguards and ePHI protection interview',
      topics: [
        'Technical safeguards for ePHI in AI systems',
        'Access control and audit controls for AI tools handling PHI',
        'Encryption and transmission security for AI-processed ePHI',
        'Incident response for PHI breach involving AI',
        'Vendor and Business Associate security obligations',
      ],
      questions: [
        {
          text: 'What technical safeguards (encryption, access control, audit logging) are in place for AI systems that process ePHI?',
          nist: ['MANAGE 1.1', 'MEASURE 2.7'],
          regs: ['HIPAA §164.312(a)', 'HIPAA §164.312(b)'],
        },
        {
          text: 'Are AI systems that access ePHI subject to unique user identification and automatic session timeouts as required by the HIPAA Technical Safeguards?',
          nist: ['GOVERN 4.1', 'MANAGE 2.2'],
          regs: ['HIPAA §164.312(a)(2)(i)', 'HIPAA §164.312(a)(2)(iii)'],
        },
        {
          text: 'How is ePHI encrypted in transit when sent to or received from a third-party AI model or cloud-based AI service?',
          nist: ['MEASURE 2.5', 'MANAGE 1.1'],
          regs: ['HIPAA §164.312(e)(2)(ii)', 'HITECH §13401'],
        },
        {
          text: 'Are audit logs for AI access to ePHI generated, protected from tampering, and reviewed on a defined schedule?',
          nist: ['MEASURE 4.1', 'MANAGE 2.2'],
          regs: ['HIPAA §164.312(b)', 'HIPAA §164.308(a)(1)'],
        },
        {
          text: 'Has a risk analysis been performed specifically for each AI system or tool that contacts ePHI datastores?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['HIPAA §164.308(a)(1)(ii)(A)', 'HITECH §13401'],
        },
        {
          text: 'What is the incident response procedure if an AI system inadvertently exposes or exfiltrates ePHI — who is notified, and within what timeframe?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['HIPAA §164.308(a)(6)', 'HITECH §13401'],
        },
        {
          text: 'How do you verify that Business Associates operating AI systems on your behalf maintain equivalent technical safeguards?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['HIPAA §164.308(b)', 'HIPAA §164.312'],
        },
      ],
    },
    legal_or_compliance: {
      roleLabel: 'Legal / Compliance',
      domain: 'compliance',
      suggestedTitle: 'Legal & Compliance — HIPAA AI obligations and BAA review interview',
      topics: [
        'HIPAA applicability and AI classification',
        'Business Associate Agreement review for AI vendors',
        'Minimum necessary and de-identification standards',
        'Patient consent and authorisation for AI use',
        'Adverse event and breach notification obligations',
      ],
      questions: [
        {
          text: 'Has legal counsel confirmed which AI vendors qualify as Business Associates under HIPAA, and are BAAs in place for each?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['HIPAA §164.308(b)', 'HITECH §13401'],
        },
        {
          text: 'Do your AI vendor contracts include HIPAA-specific terms covering permissible uses of PHI, breach notification obligations, and audit rights?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['HIPAA §164.308(b)(1)', 'HIPAA §164.502'],
        },
        {
          text: 'Has legal reviewed whether AI-generated de-identified data meets the HIPAA Expert Determination or Safe Harbor standard before use in model training?',
          nist: ['MEASURE 2.5', 'MAP 1.5'],
          regs: ['HIPAA §164.502(d)', 'HIPAA §164.514'],
        },
        {
          text: 'Is there a documented patient authorisation framework for uses of PHI in AI systems that fall outside treatment, payment, and operations?',
          nist: ['GOVERN 1.1', 'MEASURE 2.5'],
          regs: ['HIPAA §164.502(a)', 'HIPAA §164.508'],
        },
        {
          text: 'What is the legal obligation and current process for notifying HHS and patients following a PHI breach caused by an AI system?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['HITECH §13401', 'HIPAA §164.502'],
        },
        {
          text: 'How does legal track FDA SaMD guidance for AI-enabled clinical decision support — and has any deployed tool been assessed for Software as a Medical Device classification?',
          nist: ['MAP 5.2', 'GOVERN 1.7'],
          regs: ['FDA SaMD', 'HIPAA §164.308'],
        },
        {
          text: 'Are there any pending or historical OCR investigations, HIPAA audits, or settlements that affect how the organisation may deploy AI tools involving PHI?',
          nist: ['GOVERN 1.5', 'MAP 5.1'],
          regs: ['HIPAA §164.308(a)(1)', 'HITECH §13401'],
        },
      ],
    },
    compliance_owner: {
      roleLabel: 'Compliance Owner',
      domain: 'compliance',
      suggestedTitle: 'Compliance Owner — HIPAA AI compliance programme and audit readiness interview',
      topics: [
        'HIPAA compliance register for AI systems',
        'HIPAA risk analysis coverage of AI',
        'Training obligations for staff using AI with PHI',
        'Sanction policy and enforcement for AI misuse',
        'Audit readiness for OCR or third-party HIPAA review',
      ],
      questions: [
        {
          text: 'Is there a compliance register that maps each AI system to its HIPAA applicability determination and associated controls?',
          nist: ['GOVERN 1.1', 'MAP 5.2'],
          regs: ['HIPAA §164.308(a)(1)', 'HIPAA §164.312'],
        },
        {
          text: 'Does the HIPAA Security Risk Analysis cover all AI systems that store, transmit, or process ePHI — including cloud-based AI APIs?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['HIPAA §164.308(a)(1)(ii)(A)', 'HITECH §13401'],
        },
        {
          text: 'Is HIPAA training for staff who use AI systems current, role-specific, and documented with completion records?',
          nist: ['GOVERN 1.6', 'MAP 5.2'],
          regs: ['HIPAA §164.308(a)(5)', 'HITECH §13401'],
        },
        {
          text: 'Does the sanction policy explicitly address inappropriate use of AI tools to access, share, or expose PHI — and has it ever been applied?',
          nist: ['GOVERN 1.3', 'MAP 3.5'],
          regs: ['HIPAA §164.308(a)(1)(ii)(C)', 'HIPAA §164.502'],
        },
        {
          text: 'How would you demonstrate HIPAA AI compliance readiness if the OCR requested documentation today — which artefacts are immediately available?',
          nist: ['GOVERN 5.1', 'MEASURE 4.1'],
          regs: ['HIPAA §164.308', 'HIPAA §164.312'],
        },
        {
          text: 'Are AI-specific controls included in the organisation\'s periodic HIPAA control testing or internal audit programme?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['HIPAA §164.308(a)(8)', 'HITECH §13401'],
        },
      ],
    },
    ai_system_owner: {
      roleLabel: 'AI System Owner',
      domain: 'ai_governance',
      suggestedTitle: 'AI System Owner — HIPAA AI system scope, PHI data flows, and clinical safety interview',
      topics: [
        'PHI data flows into and out of the AI system',
        'Clinical decision support classification and oversight',
        'EHR integration and data access controls',
        'Model monitoring for clinical accuracy and safety',
        'Adverse event and error reporting',
      ],
      questions: [
        {
          text: 'What categories of PHI (e.g. diagnosis codes, medication records, imaging) does this AI system receive, generate, or store?',
          nist: ['MAP 1.5', 'MEASURE 2.5'],
          regs: ['HIPAA §164.502', 'HIPAA §164.312'],
        },
        {
          text: 'How does the system integrate with EHR or clinical data systems — what data access controls and audit trails exist at the integration point?',
          nist: ['MANAGE 2.2', 'MEASURE 4.1'],
          regs: ['HIPAA §164.312(a)', 'HIPAA §164.312(b)'],
        },
        {
          text: 'Is this AI system considered Clinical Decision Support software — and if so, has it been assessed for FDA SaMD classification?',
          nist: ['MAP 5.1', 'GOVERN 1.1'],
          regs: ['FDA SaMD', 'HIPAA §164.308'],
        },
        {
          text: 'How is the model monitored in production for clinical accuracy — and what thresholds trigger a safety review or temporary deactivation?',
          nist: ['MANAGE 2.2', 'MEASURE 4.1'],
          regs: ['FDA SaMD', 'HIPAA §164.308(a)(1)'],
        },
        {
          text: 'What is the process for reporting and documenting an adverse event or near-miss caused by an AI recommendation or output?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['FDA SaMD', 'HIPAA §164.308(a)(6)'],
        },
        {
          text: 'How are patients informed that AI is involved in their care pathway, and is there a documented consent or disclosure process?',
          nist: ['GOVERN 1.1', 'MAP 1.6'],
          regs: ['HIPAA §164.502', 'HIPAA §164.508'],
        },
        {
          text: 'Has the system been tested for bias across protected patient populations (age, race, sex, disability) that could affect clinical recommendations?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['HIPAA §164.502', 'FDA SaMD'],
        },
      ],
    },
    system_owner: {
      roleLabel: 'System Owner',
      domain: 'operational_security',
      suggestedTitle: 'System Owner — HIPAA system configuration, ePHI controls, and continuity interview',
      topics: [
        'ePHI data flows and access controls in integrated systems',
        'HIPAA technical safeguard implementation',
        'Patch management and vulnerability response for systems touching PHI',
        'Backup and disaster recovery for ePHI',
        'BAA implications for system dependencies',
      ],
      questions: [
        {
          text: 'Which components of your system store or transmit ePHI — are they fully inventoried and covered by the HIPAA risk analysis?',
          nist: ['MAP 1.5', 'MEASURE 2.5'],
          regs: ['HIPAA §164.308(a)(1)', 'HIPAA §164.312'],
        },
        {
          text: 'How is access to ePHI within your system controlled, monitored, and revoked when a user\'s role changes or they leave?',
          nist: ['GOVERN 4.1', 'MANAGE 2.2'],
          regs: ['HIPAA §164.312(a)(2)(i)', 'HIPAA §164.308(a)(4)'],
        },
        {
          text: 'How quickly are security patches applied to systems that store or process ePHI — is there a defined SLA for critical vulnerabilities?',
          nist: ['MANAGE 1.1', 'GOVERN 1.7'],
          regs: ['HIPAA §164.308(a)(5)', 'HIPAA §164.312'],
        },
        {
          text: 'What is the backup and recovery plan for ePHI held in this system — when were backups last tested for restoration integrity?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['HIPAA §164.308(a)(7)', 'HITECH §13401'],
        },
        {
          text: 'Do any third-party integrations or sub-processors receive ePHI from this system — and are BAAs in place for each?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['HIPAA §164.308(b)', 'HIPAA §164.502'],
        },
        {
          text: 'Is all ePHI encrypted at rest and in transit within and between components of this system?',
          nist: ['MEASURE 2.5', 'MANAGE 1.1'],
          regs: ['HIPAA §164.312(a)(2)(iv)', 'HIPAA §164.312(e)(2)(ii)'],
        },
      ],
    },
    privacy_officer: {
      roleLabel: 'Privacy Officer',
      domain: 'data_security',
      suggestedTitle: 'Privacy Officer — HIPAA PHI use in AI, patient rights, and consent interview',
      topics: [
        'PHI categories processed by AI systems',
        'Patient authorisation and minimum necessary standard',
        'Data subject rights for AI-processed PHI',
        'De-identification and safe harbour compliance',
        'DPIA and bias assessment for clinical AI',
      ],
      questions: [
        {
          text: 'Which AI systems in your environment process PHI, and has each been classified for its permissible uses under the HIPAA Privacy Rule?',
          nist: ['MEASURE 2.5', 'GOVERN 1.1'],
          regs: ['HIPAA §164.502', 'HIPAA §164.508'],
        },
        {
          text: 'Is the minimum necessary standard applied when PHI is passed to AI systems — is only the data genuinely required for the AI function transmitted?',
          nist: ['MEASURE 2.5', 'MAP 1.5'],
          regs: ['HIPAA §164.502(b)', 'HIPAA §164.514'],
        },
        {
          text: 'How do you handle patient requests to restrict or object to their PHI being used in AI-assisted clinical or operational processes?',
          nist: ['MEASURE 2.5', 'GOVERN 1.7'],
          regs: ['HIPAA §164.502(a)', 'HIPAA §164.522'],
        },
        {
          text: 'When PHI is used for AI model training, has it been de-identified to HIPAA Safe Harbor or Expert Determination standard — and is that determination documented?',
          nist: ['MEASURE 2.5', 'MAP 1.5'],
          regs: ['HIPAA §164.502(d)', 'HIPAA §164.514'],
        },
        {
          text: 'Has a Privacy Impact Assessment or DPIA been completed for AI systems that process large volumes of PHI or use PHI for purposes beyond direct care?',
          nist: ['MAP 5.1', 'MEASURE 2.5'],
          regs: ['HIPAA §164.308(a)(1)', 'HIPAA §164.502'],
        },
        {
          text: 'How are patients notified when AI systems are involved in decisions about their care — and is this disclosure captured in the Notice of Privacy Practices?',
          nist: ['MAP 1.6', 'GOVERN 1.1'],
          regs: ['HIPAA §164.502', 'HIPAA §164.520'],
        },
        {
          text: 'Has any AI system been assessed for racially or demographically disparate outputs that could constitute discriminatory use of PHI?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['HIPAA §164.502', 'FDA SaMD'],
        },
      ],
    },
  },

  // ── PCI DSS v4.0 ─────────────────────────────────────────────────────────
  pci_dss: {
    executive_sponsor: {
      roleLabel: 'Executive Sponsor',
      domain: 'ai_governance',
      suggestedTitle: 'Executive Sponsor — PCI DSS AI governance and cardholder data risk interview',
      topics: [
        'AI systems in or adjacent to the Cardholder Data Environment',
        'Board-level PCI DSS AI risk appetite',
        'Emerging technology risk assessment obligations (Req 12.3)',
        'Liability and brand exposure from AI-related card data breach',
        'Third-party service provider AI obligations',
      ],
      questions: [
        {
          text: 'Are any AI tools or systems deployed within or directly connected to the Cardholder Data Environment (CDE), or do they process, transmit, or store PAN, CVV, or track data?',
          nist: ['GOVERN 1.1', 'MAP 1.1'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'Has a formal targeted risk analysis been completed for each AI system that could affect the CDE, as required by PCI DSS v4.0 Requirement 12.3?',
          nist: ['MAP 5.1', 'GOVERN 2.1'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'How does executive leadership ensure that third-party service providers (TPSPs) offering AI capabilities maintain PCI DSS compliance obligations?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'What is the organisation\'s risk appetite for using AI in fraud detection, customer authentication, or payment processing workflows?',
          nist: ['GOVERN 2.1', 'GOVERN 2.2'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'How are AI-related changes to CDE-adjacent systems governed — what approval process applies before deployment?',
          nist: ['GOVERN 1.1', 'GOVERN 4.1'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Have there been any AI-related security incidents or near-misses involving cardholder data in the past 12 months?',
          nist: ['MANAGE 2.4', 'MAP 3.5'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
      ],
    },
    security_owner: {
      roleLabel: 'Security Owner',
      domain: 'ai_governance',
      suggestedTitle: 'Security Owner — PCI DSS AI security controls and CDE risk interview',
      topics: [
        'AI system scope relative to the CDE',
        'Authentication and access controls for AI tools (Req 8)',
        'Vulnerability and change management for AI in scope (Req 6)',
        'Logging and monitoring of AI accessing cardholder data',
        'AI model integrity and tampering controls',
      ],
      questions: [
        {
          text: 'Have you formally scoped each AI system against the CDE — specifically whether it stores, processes, or transmits PAN or other cardholder data?',
          nist: ['GOVERN 1.1', 'MAP 5.1'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'Are unique user IDs, MFA, and role-based access controls enforced for all users and service accounts that access AI systems in or connected to the CDE?',
          nist: ['MANAGE 1.1', 'GOVERN 4.1'],
          regs: ['PCI DSS v4.0 Req 8.2', 'PCI DSS v4.0 Req 8.6'],
        },
        {
          text: 'How are AI components (model weights, inference APIs, training pipelines) included in the vulnerability management programme — are they scanned and patched on the same schedule as other CDE systems?',
          nist: ['MANAGE 1.1', 'MEASURE 2.7'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Is access to AI tools that interact with cardholder data logged to an immutable audit trail, and are those logs reviewed and retained per PCI DSS requirements?',
          nist: ['MEASURE 4.1', 'MANAGE 2.2'],
          regs: ['PCI DSS v4.0 Req 10.2', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'What controls detect and prevent AI model tampering, prompt injection, or adversarial manipulation that could expose cardholder data?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Has a targeted risk analysis been performed for AI-specific threats (data poisoning, model inversion, API abuse) within the CDE context?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'How are AI service account credentials (API keys, tokens, model endpoint secrets) managed, rotated, and protected within the CDE?',
          nist: ['MANAGE 2.2', 'GOVERN 4.1'],
          regs: ['PCI DSS v4.0 Req 8.2', 'PCI DSS v4.0 Req 8.6'],
        },
      ],
    },
    legal_or_compliance: {
      roleLabel: 'Legal / Compliance',
      domain: 'compliance',
      suggestedTitle: 'Legal & Compliance — PCI DSS AI obligations and TPSP contract review interview',
      topics: [
        'PCI DSS v4.0 applicability to AI deployments',
        'TPSP AI contract terms and responsibility matrix',
        'Req 12.3 targeted risk analysis obligations',
        'Liability and brand exposure from card data breach via AI',
        'Regulatory and card brand reporting for AI-related incidents',
      ],
      questions: [
        {
          text: 'Has legal confirmed which AI vendors qualify as third-party service providers (TPSPs) under PCI DSS v4.0 — and are their PCI DSS compliance statuses documented?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Do TPSP agreements for AI vendors include a responsibility matrix clarifying which PCI DSS requirements the vendor owns vs. the merchant/acquirer?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Are there contractual obligations requiring AI vendors to notify the organisation of changes that could affect the cardholder data in scope or PCI DSS compliance posture?',
          nist: ['GOVERN 4.2', 'MANAGE 3.1'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'What is the legal obligation and timeline to report to card brands (Visa, Mastercard) and acquiring banks if an AI system is involved in a cardholder data compromise?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Has legal reviewed whether AI tools used for fraud scoring or transaction monitoring create any IP, liability, or consumer protection exposure?',
          nist: ['MAP 5.1', 'GOVERN 1.1'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'How does the organisation track and respond to PCI SSC guidance on AI and emerging technologies as it evolves under v4.0?',
          nist: ['GOVERN 1.7', 'MAP 5.2'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 12.4'],
        },
      ],
    },
    compliance_owner: {
      roleLabel: 'Compliance Owner',
      domain: 'compliance',
      suggestedTitle: 'Compliance Owner — PCI DSS v4.0 AI compliance programme and QSA readiness interview',
      topics: [
        'PCI DSS scope determination for AI systems',
        'Req 12.3 targeted risk analysis documentation',
        'AI inclusion in SAQ / ROC evidence packages',
        'Control testing for AI components in the CDE',
        'Training and awareness obligations for AI tool users',
      ],
      questions: [
        {
          text: 'How are AI systems evaluated for PCI DSS scope — what criteria determine whether a system is in-scope for the CDE or connected-to-CDE classification?',
          nist: ['GOVERN 1.1', 'MAP 5.2'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'Are targeted risk analyses (as required by Req 12.3) completed and documented for each in-scope AI system, and are they reviewed at least annually?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'Are AI systems included in the evidence package provided to the QSA during ROC or SAQ assessment — and are AI-specific control descriptions adequate?',
          nist: ['GOVERN 5.1', 'MEASURE 4.1'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'How frequently are AI-specific controls (access control, logging, vulnerability scanning for AI components) formally tested?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 8.2'],
        },
        {
          text: 'Are staff who use or administer AI systems in the CDE given PCI DSS training that specifically covers AI-related risks and acceptable use?',
          nist: ['GOVERN 1.6', 'MAP 5.2'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'How are changes to AI models or AI vendor configurations tracked through the change management process to avoid unintended scope expansion?',
          nist: ['GOVERN 1.7', 'MANAGE 1.1'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
      ],
    },
    ai_system_owner: {
      roleLabel: 'AI System Owner',
      domain: 'ai_governance',
      suggestedTitle: 'AI System Owner — PCI DSS cardholder data flows, model integrity, and CDE controls interview',
      topics: [
        'Cardholder data types processed by the AI system',
        'CDE boundary and network segmentation for AI',
        'Model integrity and adversarial threat controls',
        'Change management for AI models in scope',
        'Third-party AI model and API risk',
      ],
      questions: [
        {
          text: 'Does this AI system ever receive, process, store, or transmit PAN, CVV, expiry date, cardholder name, or track data — even transiently?',
          nist: ['MAP 1.5', 'MEASURE 2.5'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'How is the AI system segmented from the CDE — is there documented network segmentation, and has it been validated by testing?',
          nist: ['MANAGE 1.1', 'MEASURE 2.7'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'What controls detect adversarial manipulation of the AI model (prompt injection, data poisoning) that could lead to cardholder data exposure or fraudulent transaction approval?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'How are changes to model weights, training data, or inference APIs reviewed and approved — and is there a rollback plan if a model change introduces a security vulnerability?',
          nist: ['MANAGE 1.1', 'GOVERN 1.7'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'If this AI system uses a third-party model API (e.g. a cloud-based LLM), how is cardholder data prevented from being sent to the external provider?',
          nist: ['GOVERN 4.1', 'MEASURE 2.5'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 8.2'],
        },
        {
          text: 'How are AI service account credentials and API keys for CDE-connected systems managed, rotated, and audited?',
          nist: ['MANAGE 2.2', 'MEASURE 4.1'],
          regs: ['PCI DSS v4.0 Req 8.2', 'PCI DSS v4.0 Req 8.6'],
        },
        {
          text: 'Has a targeted risk analysis specific to this AI system been completed and documented per PCI DSS v4.0 Req 12.3?',
          nist: ['MAP 5.1', 'GOVERN 2.1'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
      ],
    },
    system_owner: {
      roleLabel: 'System Owner',
      domain: 'operational_security',
      suggestedTitle: 'System Owner — PCI DSS system configuration and CDE controls interview',
      topics: [
        'System scope and CDE boundary definition',
        'Access controls for in-scope systems',
        'Vulnerability management for CDE components',
        'Logging and monitoring obligations',
        'Change control for systems in the CDE',
      ],
      questions: [
        {
          text: 'Is this system formally classified as in-scope for PCI DSS — and is that determination documented and reviewed at least annually?',
          nist: ['MAP 1.1', 'GOVERN 1.2'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'How is access to this system controlled — are shared or group credentials used anywhere in the system stack, and how are service accounts managed?',
          nist: ['GOVERN 4.1', 'MANAGE 2.2'],
          regs: ['PCI DSS v4.0 Req 8.2', 'PCI DSS v4.0 Req 8.6'],
        },
        {
          text: 'How quickly are critical security patches applied to this system — and is there a documented SLA for in-scope PCI DSS systems?',
          nist: ['MANAGE 1.1', 'GOVERN 1.7'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Are all access and configuration change events on this system logged to an audit trail that is protected from modification and retained for at least 12 months?',
          nist: ['MEASURE 4.1', 'MANAGE 2.2'],
          regs: ['PCI DSS v4.0 Req 10.2', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'What is the change control process for this system — and how are emergency changes to CDE-adjacent systems approved and documented?',
          nist: ['GOVERN 1.7', 'MANAGE 1.1'],
          regs: ['PCI DSS v4.0 Req 6.3', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'What is the business continuity and recovery plan for this system if a PCI-relevant incident occurs — and when was it last tested?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
      ],
    },
    privacy_officer: {
      roleLabel: 'Privacy Officer',
      domain: 'data_security',
      suggestedTitle: 'Privacy Officer — PCI DSS cardholder data minimisation and AI data use interview',
      topics: [
        'Cardholder data minimisation in AI inputs and outputs',
        'Data retention and deletion for AI-processed card data',
        'Cross-border data flows for AI services processing cardholder data',
        'Consumer rights and disclosure for AI-driven decisions',
        'PAN masking and tokenisation in AI workflows',
      ],
      questions: [
        {
          text: 'Are there controls that prevent full PAN, CVV, or track data from being included in prompts or inputs sent to AI systems — including internal models and third-party APIs?',
          nist: ['MEASURE 2.5', 'MANAGE 1.1'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'Is cardholder data used in AI model training — and if so, is it tokenised, masked, or otherwise de-scoped before training data is assembled?',
          nist: ['MEASURE 2.5', 'MAP 1.5'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
        {
          text: 'What is the retention schedule for cardholder data that may be captured in AI interaction logs, inference outputs, or model training artefacts?',
          nist: ['GOVERN 1.7', 'MAP 1.5'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'If cardholder data is sent to an AI vendor or cloud provider for processing, is that vendor formally classified as a TPSP, and how is their geographic data residency documented?',
          nist: ['GOVERN 4.1', 'MEASURE 2.5'],
          regs: ['PCI DSS v4.0 Req 12.4', 'PCI DSS v4.0 Req 12.3'],
        },
        {
          text: 'Are cardholders informed when AI is used in payment decisions (fraud scoring, credit decisions, dispute resolution) that directly affect them?',
          nist: ['GOVERN 1.1', 'MAP 1.6'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 12.4'],
        },
        {
          text: 'Has the organisation implemented PAN masking or tokenisation in all environments where AI systems might otherwise encounter raw cardholder data?',
          nist: ['MEASURE 2.5', 'MANAGE 1.1'],
          regs: ['PCI DSS v4.0 Req 12.3', 'PCI DSS v4.0 Req 6.3'],
        },
      ],
    },
  },

  // ── DORA (EU 2022/2554) ──────────────────────────────────────────────────
  dora: {
    executive_sponsor: {
      roleLabel: 'Executive Sponsor',
      domain: 'ai_governance',
      suggestedTitle: 'Executive Sponsor — DORA ICT operational resilience and AI governance interview',
      topics: [
        'AI as ICT systems under DORA scope',
        'Board accountability for digital operational resilience (Art. 5)',
        'ICT concentration risk from AI vendor dependency',
        'Exit strategies from critical AI providers',
        'AI in the ICT incident classification and reporting framework',
      ],
      questions: [
        {
          text: 'Which AI systems are classified as ICT systems under your DORA scope — and has that classification been formally documented and reviewed by the management body?',
          nist: ['GOVERN 1.1', 'MAP 1.1'],
          regs: ['DORA Art. 5', 'DORA Art. 9'],
        },
        {
          text: 'As a member of the management body, how do you receive and act on reports about ICT operational resilience risks involving AI systems?',
          nist: ['GOVERN 1.6', 'GOVERN 6.1'],
          regs: ['DORA Art. 5', 'DORA Art. 9'],
        },
        {
          text: 'Is there a documented concentration risk assessment covering AI providers — specifically the risk of operational dependency on a single AI platform or model provider?',
          nist: ['GOVERN 2.1', 'MAP 5.1'],
          regs: ['DORA Art. 28', 'DORA Art. 5'],
        },
        {
          text: 'Do contracts with critical AI providers include exit clauses, data portability requirements, and a documented transition plan in case the provider becomes unavailable or non-compliant?',
          nist: ['GOVERN 4.1', 'GOVERN 6.2'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'Has the organisation performed or commissioned a Threat-Led Penetration Test (TLPT) that includes AI-dependent ICT systems, as required by DORA Art. 24?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['DORA Art. 24', 'DORA Art. 5'],
        },
        {
          text: 'How does executive leadership ensure that AI-related ICT incidents are classified, reported to competent authorities within DORA timelines, and reviewed post-incident?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['DORA Art. 17', 'DORA Art. 5'],
        },
      ],
    },
    security_owner: {
      roleLabel: 'Security Owner',
      domain: 'ai_governance',
      suggestedTitle: 'Security Owner — DORA ICT security controls for AI systems interview',
      topics: [
        'AI system classification in the ICT risk management framework (Art. 9)',
        'ICT security controls for AI (access, logging, encryption)',
        'Threat-led penetration testing for AI systems (Art. 24)',
        'ICT incident detection and reporting for AI events (Art. 17)',
        'Third-party ICT provider register and AI vendor monitoring (Art. 28)',
      ],
      questions: [
        {
          text: 'How are AI systems incorporated into the ICT risk management framework — are they inventoried, classified by criticality, and subject to the same controls as other ICT systems?',
          nist: ['GOVERN 1.1', 'MAP 5.1'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
        {
          text: 'What specific ICT security controls are applied to AI systems — covering access control, encryption, logging, and network segmentation?',
          nist: ['MANAGE 1.1', 'MEASURE 2.7'],
          regs: ['DORA Art. 9', 'DORA Art. 28'],
        },
        {
          text: 'Have AI-dependent ICT systems been included in Threat-Led Penetration Testing (TLPT) planning, and if so, what findings were identified?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['DORA Art. 24', 'DORA Art. 9'],
        },
        {
          text: 'How is anomalous or potentially malicious activity in AI systems detected — and what alerts would trigger an ICT incident classification under DORA Art. 17?',
          nist: ['MEASURE 4.1', 'MANAGE 2.4'],
          regs: ['DORA Art. 17', 'DORA Art. 9'],
        },
        {
          text: 'Are AI vendors listed in the third-party ICT provider register required by DORA Art. 28 — and is each provider\'s criticality assessment current?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'What is the tested recovery time objective (RTO) for AI systems classified as supporting critical functions — and does the BCP/DR plan include AI-specific failure scenarios?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['DORA Art. 9', 'DORA Art. 17'],
        },
        {
          text: 'How does the organisation monitor AI vendor sub-processors for ICT risk — and what triggers a mandatory review of a critical AI provider relationship?',
          nist: ['GOVERN 4.2', 'MANAGE 3.1'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
      ],
    },
    legal_or_compliance: {
      roleLabel: 'Legal / Compliance',
      domain: 'compliance',
      suggestedTitle: 'Legal & Compliance — DORA AI ICT contract obligations and regulatory reporting interview',
      topics: [
        'DORA applicability to AI as ICT systems',
        'Art. 28 contractual requirements for critical ICT providers',
        'ICT incident reporting obligations (Art. 17)',
        'Concentration risk disclosure to competent authorities',
        'Exit strategy and transition planning for AI vendors',
      ],
      questions: [
        {
          text: 'Has legal confirmed which AI providers qualify as critical third-party ICT providers under DORA — and are Art. 28 contractual requirements included in each agreement?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['DORA Art. 28', 'DORA Art. 5'],
        },
        {
          text: 'Do AI vendor contracts meet DORA Art. 28 requirements — including service level descriptions, audit rights, security obligations, data location, and termination support?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'What is the legal obligation and timeline for reporting a major ICT incident involving an AI system to the competent authority under DORA Art. 17 — and who owns that process?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['DORA Art. 17', 'DORA Art. 5'],
        },
        {
          text: 'Is there a process for voluntarily notifying competent authorities of significant cyber threats related to AI systems that have not yet caused an incident, as permitted by DORA Art. 17?',
          nist: ['GOVERN 6.1', 'MAP 3.5'],
          regs: ['DORA Art. 17', 'DORA Art. 9'],
        },
        {
          text: 'Has legal assessed whether the organisation\'s AI provider concentration creates a disclosure or remediation obligation to the competent authority under DORA concentration risk provisions?',
          nist: ['MAP 5.1', 'GOVERN 1.1'],
          regs: ['DORA Art. 28', 'DORA Art. 5'],
        },
        {
          text: 'How does legal track DORA regulatory technical standards (RTS) as they are finalised by ESAs, and translate updates into contractual or policy changes for AI providers?',
          nist: ['GOVERN 1.7', 'MAP 5.2'],
          regs: ['DORA Art. 5', 'DORA Art. 28'],
        },
      ],
    },
    compliance_owner: {
      roleLabel: 'Compliance Owner',
      domain: 'compliance',
      suggestedTitle: 'Compliance Owner — DORA ICT resilience programme and AI compliance interview',
      topics: [
        'ICT risk management framework coverage of AI systems',
        'DORA digital resilience testing programme including AI',
        'ICT incident register and AI incident documentation',
        'Third-party ICT register maintenance for AI providers',
        'DORA audit readiness for AI-related requirements',
      ],
      questions: [
        {
          text: 'Is there an ICT risk management framework that explicitly covers AI systems — and are AI-specific risk scenarios documented and regularly reviewed?',
          nist: ['GOVERN 1.1', 'MAP 5.2'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
        {
          text: 'Is there a documented digital operational resilience testing programme that includes AI systems — and does it cover both vulnerability assessments and advanced TLPT where applicable?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['DORA Art. 24', 'DORA Art. 9'],
        },
        {
          text: 'Is there a register of ICT incidents involving AI systems — and does it capture the information required for DORA major incident reporting (classification, impact, root cause, remediation)?',
          nist: ['MANAGE 2.4', 'MEASURE 4.1'],
          regs: ['DORA Art. 17', 'DORA Art. 9'],
        },
        {
          text: 'Is the third-party ICT provider register current, and does it include all AI vendors with a documented criticality assessment for each?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'How would you demonstrate DORA compliance readiness for AI-related requirements to a competent authority today — which artefacts are immediately available?',
          nist: ['GOVERN 5.1', 'MEASURE 4.1'],
          regs: ['DORA Art. 5', 'DORA Art. 9'],
        },
        {
          text: 'How are lessons learned from AI-related ICT incidents or resilience tests fed back into updated controls, training, or the ICT risk management framework?',
          nist: ['GOVERN 1.7', 'MANAGE 1.3'],
          regs: ['DORA Art. 17', 'DORA Art. 24'],
        },
      ],
    },
    ai_system_owner: {
      roleLabel: 'AI System Owner',
      domain: 'ai_governance',
      suggestedTitle: 'AI System Owner — DORA ICT risk, resilience testing, and third-party AI dependency interview',
      topics: [
        'AI system criticality classification under DORA',
        'ICT continuity and recovery for AI systems',
        'TLPT scope and AI system inclusion (Art. 24)',
        'AI provider dependency and exit planning (Art. 28)',
        'ICT incident detection and classification for AI events',
      ],
      questions: [
        {
          text: 'How is this AI system classified within the ICT criticality framework — and what functions would be impaired if it became unavailable for 2 hours, 4 hours, or 24 hours?',
          nist: ['MAP 1.1', 'GOVERN 1.2'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
        {
          text: 'What are the recovery time objective (RTO) and recovery point objective (RPO) for this AI system — and have they been validated through a documented recovery test?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['DORA Art. 9', 'DORA Art. 17'],
        },
        {
          text: 'Has this AI system been included in TLPT planning under DORA Art. 24 — and if not, what is the rationale for exclusion?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['DORA Art. 24', 'DORA Art. 9'],
        },
        {
          text: 'If the primary AI vendor or model provider became unavailable, what is the exit and transition plan — and how quickly could the organisation switch to an alternative?',
          nist: ['GOVERN 4.1', 'GOVERN 6.2'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'What events in this AI system would be classified as a major ICT incident under DORA Art. 17 — and what is the detection-to-classification time objective?',
          nist: ['MANAGE 2.4', 'MEASURE 4.1'],
          regs: ['DORA Art. 17', 'DORA Art. 9'],
        },
        {
          text: 'Are the AI provider\'s sub-processors and data locations documented — and does the organisation have contractual visibility into material changes to the provider\'s own supply chain?',
          nist: ['GOVERN 4.2', 'MANAGE 3.1'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'How are changes to the AI model or provider infrastructure communicated by the vendor — and what review process applies before accepting a significant model update?',
          nist: ['MANAGE 1.1', 'GOVERN 1.7'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
      ],
    },
    system_owner: {
      roleLabel: 'System Owner',
      domain: 'operational_security',
      suggestedTitle: 'System Owner — DORA ICT continuity and system resilience interview',
      topics: [
        'ICT criticality and DORA scope determination for the system',
        'Continuity and recovery testing obligations',
        'Third-party ICT dependencies and exit planning',
        'ICT incident detection and reporting for the system',
        'Change management within DORA ICT risk framework',
      ],
      questions: [
        {
          text: 'Has this system been formally assessed for DORA ICT criticality — and what business functions would be materially impaired if it became unavailable?',
          nist: ['MAP 1.1', 'GOVERN 1.2'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
        {
          text: 'When were the RTO and RPO for this system last tested — and did the test results confirm that recovery targets are achievable?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['DORA Art. 9', 'DORA Art. 17'],
        },
        {
          text: 'Which third-party ICT providers support this system — are they listed in the DORA Art. 28 register, and are contracts current with the required DORA provisions?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'What monitoring is in place to detect ICT incidents affecting this system — and what criteria trigger escalation to the ICT incident classification process?',
          nist: ['MEASURE 4.1', 'MANAGE 2.4'],
          regs: ['DORA Art. 17', 'DORA Art. 9'],
        },
        {
          text: 'How are changes to this system governed — and is there a review step that specifically considers ICT operational resilience impact before deployment?',
          nist: ['GOVERN 1.7', 'MANAGE 1.1'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
      ],
    },
    privacy_officer: {
      roleLabel: 'Privacy Officer',
      domain: 'data_security',
      suggestedTitle: 'Privacy Officer — DORA AI data processing, cross-border flows, and subject rights interview',
      topics: [
        'Personal data in AI ICT systems under DORA scope',
        'Cross-border data transfers to AI providers',
        'Data subject rights for AI-processed personal data',
        'Retention and deletion for AI interaction data',
        'DPIA obligations for high-risk AI ICT systems',
      ],
      questions: [
        {
          text: 'Which AI systems in the DORA ICT scope process personal data — and is there a legal basis documented for each type of personal data processing?',
          nist: ['MEASURE 2.5', 'GOVERN 1.1'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
        {
          text: 'Do any critical AI providers process personal data outside the EEA — and if so, what transfer mechanism (SCCs, adequacy decision) is in place and is it current?',
          nist: ['GOVERN 4.1', 'MEASURE 2.5'],
          regs: ['DORA Art. 28', 'DORA Art. 9'],
        },
        {
          text: 'How are data subject rights (access, erasure, restriction) handled for personal data that has been processed by or logged within DORA-scoped AI systems?',
          nist: ['MEASURE 2.5', 'GOVERN 1.7'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
        {
          text: 'What are the retention and deletion schedules for personal data captured in AI interaction logs, model outputs, or ICT incident records?',
          nist: ['GOVERN 1.7', 'MAP 1.5'],
          regs: ['DORA Art. 9', 'DORA Art. 17'],
        },
        {
          text: 'Has a DPIA been completed for AI systems classified as high-risk under both GDPR and DORA — and were ICT resilience risks to personal data included in the DPIA scope?',
          nist: ['MAP 5.1', 'MEASURE 2.5'],
          regs: ['DORA Art. 9', 'DORA Art. 5'],
        },
        {
          text: 'If an ICT incident involving an AI system results in a personal data breach, what is the coordinated GDPR breach notification and DORA incident reporting process?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['DORA Art. 17', 'DORA Art. 9'],
        },
      ],
    },
  },

  // ── Government (CMMC 2.0 / FedRAMP / NIST 800-171 / EO 14110) ────────────
  government: {
    executive_sponsor: {
      roleLabel: 'Executive Sponsor',
      domain: 'ai_governance',
      suggestedTitle: 'Executive Sponsor — CMMC/FedRAMP AI governance and CUI risk interview',
      topics: [
        'AI systems processing CUI and CMMC Level obligations',
        'Board-level accountability for federal AI compliance (EO 14110)',
        'AI vendor FedRAMP authorisation requirements',
        'System Security Plan coverage of AI systems',
        'Supply chain risk for AI components (SCRM)',
      ],
      questions: [
        {
          text: 'Which AI systems in use by the organisation process, store, or transmit Controlled Unclassified Information (CUI) — and have they been formally identified in the System Security Plan?',
          nist: ['GOVERN 1.1', 'MAP 1.1'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'What CMMC Level is required by current or anticipated federal contracts — and how has the organisation assessed whether AI system usage affects CMMC Level 2 or Level 3 compliance?',
          nist: ['GOVERN 1.2', 'MAP 5.1'],
          regs: ['CMMC AC.1.001', 'NIST 800-171 §3.1.1'],
        },
        {
          text: 'Do any AI tools used in federal contract work use cloud services that are not FedRAMP Authorized — and if so, how is that risk managed and documented?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['FedRAMP AC-2', 'NIST 800-171 §3.13.1'],
        },
        {
          text: 'How does executive leadership ensure compliance with EO 14110 on the Safe, Secure, and Trustworthy Development and Use of Artificial Intelligence when AI is used in federal contract performance?',
          nist: ['GOVERN 1.5', 'MAP 1.5'],
          regs: ['EO 14110', 'NIST 800-171 §3.1.1'],
        },
        {
          text: 'Is there a supply chain risk management (SCRM) programme that evaluates AI component and model vendors for foreign ownership, control, or influence (FOCI) risks?',
          nist: ['GOVERN 4.1', 'MAP 5.1'],
          regs: ['NIST 800-171 §3.13.1', 'CMMC SI.1.210'],
        },
        {
          text: 'What is the executive escalation path if an AI system is found to have processed CUI without being covered in the SSP or without adequate controls?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
      ],
    },
    security_owner: {
      roleLabel: 'Security Owner',
      domain: 'ai_governance',
      suggestedTitle: 'Security Owner — CMMC/FedRAMP AI security controls and CUI protection interview',
      topics: [
        'CUI access controls for AI systems (NIST 800-171 §3.1)',
        'System Security Plan coverage of AI tools',
        'Audit and accountability for AI accessing CUI (NIST 800-171 §3.3)',
        'Configuration management for AI components (NIST 800-171 §3.4)',
        'Supply chain risk for AI models and providers',
      ],
      questions: [
        {
          text: 'Are all AI systems that could access CUI covered in the System Security Plan — including cloud-based AI APIs, LLMs used by staff, and AI-assisted analysis tools?',
          nist: ['GOVERN 1.1', 'MAP 5.1'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'How is access to AI systems that process CUI controlled — are access rights granted based on the principle of least privilege and tied to a specific contract or project need?',
          nist: ['MANAGE 1.1', 'GOVERN 4.1'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Are actions by users and service accounts accessing CUI through AI systems logged to an audit trail that is protected, reviewed, and retained for the required period?',
          nist: ['MEASURE 4.1', 'MANAGE 2.2'],
          regs: ['NIST 800-171 §3.3.1', 'CMMC AC.1.001'],
        },
        {
          text: 'How are AI components (model weights, inference endpoints, training pipelines) included in the configuration management baseline — and are changes reviewed and authorised?',
          nist: ['MANAGE 1.1', 'GOVERN 1.7'],
          regs: ['NIST 800-171 §3.4.1', 'CMMC SI.1.210'],
        },
        {
          text: 'Has a supply chain risk assessment been completed for AI model providers — including review of country of origin, ownership structure, and known vulnerabilities?',
          nist: ['GOVERN 4.1', 'MAP 5.1'],
          regs: ['NIST 800-171 §3.13.1', 'CMMC SI.1.210'],
        },
        {
          text: 'Are there POA&M entries for any identified gaps in AI security controls — and what is the remediation timeline for each open item?',
          nist: ['MAP 5.1', 'MANAGE 1.3'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'How is insider threat risk managed for staff with AI tool access to CUI — are there monitoring controls, separation of duties, and periodic access reviews?',
          nist: ['MAP 3.5', 'GOVERN 4.2'],
          regs: ['NIST 800-171 §3.3.2', 'CMMC SI.1.210'],
        },
      ],
    },
    legal_or_compliance: {
      roleLabel: 'Legal / Compliance',
      domain: 'compliance',
      suggestedTitle: 'Legal & Compliance — CMMC/FedRAMP AI contract obligations and regulatory interview',
      topics: [
        'CMMC flowdown requirements for AI in subcontracts',
        'FedRAMP authorisation requirements for AI cloud services',
        'DFARS 252.204-7012 and CUI obligations for AI',
        'EO 14110 compliance obligations for federal AI use',
        'Incident reporting obligations for CUI breaches via AI',
      ],
      questions: [
        {
          text: 'Are CMMC requirements flowed down to subcontractors and AI vendors who handle CUI on behalf of the prime — and is this documented in subcontracts?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['CMMC AC.1.001', 'NIST 800-171 §3.13.1'],
        },
        {
          text: 'Do federal contracts that involve AI systems reference DFARS 252.204-7012 (Safeguarding Covered Defense Information) — and is the organisation clear on its obligations under that clause?',
          nist: ['GOVERN 1.1', 'MAP 5.2'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Has legal confirmed whether AI cloud services used in federal contract performance are FedRAMP Authorized at the appropriate impact level (Moderate or High)?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['FedRAMP AC-2', 'NIST 800-171 §3.13.1'],
        },
        {
          text: 'What is the legal obligation and timeline for reporting a CUI breach caused by an AI system to the relevant federal agency or DoD CUI Officer?',
          nist: ['MANAGE 2.4', 'GOVERN 6.1'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'How does legal track EO 14110 implementation requirements and any emerging federal AI use policy that affects the organisation\'s federal contract performance?',
          nist: ['GOVERN 1.7', 'MAP 5.2'],
          regs: ['EO 14110', 'NIST 800-171 §3.1.1'],
        },
        {
          text: 'Are there any export control (EAR/ITAR) implications for AI tools or models used in connection with federal contracts involving controlled technical data?',
          nist: ['MAP 5.1', 'GOVERN 4.1'],
          regs: ['NIST 800-171 §3.13.1', 'CMMC SI.1.210'],
        },
      ],
    },
    compliance_owner: {
      roleLabel: 'Compliance Owner',
      domain: 'compliance',
      suggestedTitle: 'Compliance Owner — CMMC/FedRAMP AI compliance programme and assessment readiness interview',
      topics: [
        'NIST 800-171 control coverage for AI systems',
        'SSP documentation of AI tools and their control applicability',
        'POA&M management for AI security gaps',
        'CMMC assessment readiness for AI-related requirements',
        'Training obligations for staff handling CUI via AI',
      ],
      questions: [
        {
          text: 'Are all AI systems that could process CUI documented in the System Security Plan — including their control applicability, inherited controls, and responsible parties?',
          nist: ['GOVERN 1.1', 'MAP 5.2'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Are there open POA&M items related to AI security gaps — and what is the prioritisation and timeline for remediation?',
          nist: ['MAP 5.1', 'MANAGE 1.3'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'How would you demonstrate CMMC compliance readiness for AI-related NIST 800-171 controls to a C3PAO assessor today — which artefacts are immediately available?',
          nist: ['GOVERN 5.1', 'MEASURE 4.1'],
          regs: ['CMMC AC.1.001', 'NIST 800-171 §3.1.1'],
        },
        {
          text: 'Is there mandatory training for staff who use AI tools in federal contract performance — covering CUI handling obligations, acceptable AI use, and insider threat awareness?',
          nist: ['GOVERN 1.6', 'MAP 5.2'],
          regs: ['NIST 800-171 §3.3.2', 'CMMC SI.1.210'],
        },
        {
          text: 'How are AI-specific controls tested as part of the NIST 800-171 self-assessment or third-party CMMC assessment — is there documented evidence for each control?',
          nist: ['MEASURE 2.7', 'MANAGE 1.3'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'How does the organisation track changes to CMMC rulemaking, NIST SP 800-171 Rev 3, and federal AI policy — and how are those changes reflected in the SSP and control set?',
          nist: ['GOVERN 1.7', 'MAP 5.2'],
          regs: ['NIST 800-171 §3.13.1', 'EO 14110'],
        },
      ],
    },
    ai_system_owner: {
      roleLabel: 'AI System Owner',
      domain: 'ai_governance',
      suggestedTitle: 'AI System Owner — CMMC/FedRAMP CUI protection, SSP coverage, and supply chain interview',
      topics: [
        'CUI data flows in and out of the AI system',
        'SSP coverage and control inheritance for the AI system',
        'Supply chain risk for AI model or platform provider',
        'Insider threat controls for AI CUI access',
        'Monitoring and incident response for AI CUI events',
      ],
      questions: [
        {
          text: 'What categories of CUI does this AI system process — and is each category and its handling requirement documented in the System Security Plan?',
          nist: ['MAP 1.5', 'MEASURE 2.5'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Which NIST 800-171 controls apply to this AI system — and how many are fully implemented, partially implemented, or documented as POA&M items?',
          nist: ['MAP 5.1', 'MEASURE 2.7'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Has a supply chain risk assessment been performed for the AI model or platform provider — covering country of origin, FOCI risk, and known CVEs in the model?',
          nist: ['GOVERN 4.1', 'MAP 5.1'],
          regs: ['NIST 800-171 §3.13.1', 'CMMC SI.1.210'],
        },
        {
          text: 'How is the principle of least privilege enforced for access to this AI system — can only authorised users with a contract-related need access CUI-bearing AI features?',
          nist: ['MANAGE 2.2', 'GOVERN 4.1'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Are user actions on this AI system logged to an audit trail that captures who accessed CUI, when, and what AI operations were performed?',
          nist: ['MEASURE 4.1', 'MANAGE 2.2'],
          regs: ['NIST 800-171 §3.3.1', 'CMMC AC.1.001'],
        },
        {
          text: 'What would happen if a CUI document was inadvertently uploaded or submitted to this AI system — is there a detection, containment, and notification process?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC SI.1.210'],
        },
        {
          text: 'If this AI system uses a cloud-based model or API endpoint, is that provider FedRAMP Authorized at the Moderate or High impact level — and is the authorisation current?',
          nist: ['GOVERN 4.1', 'MANAGE 3.1'],
          regs: ['FedRAMP AC-2', 'NIST 800-171 §3.13.1'],
        },
      ],
    },
    system_owner: {
      roleLabel: 'System Owner',
      domain: 'operational_security',
      suggestedTitle: 'System Owner — CMMC/FedRAMP system configuration, CUI controls, and continuity interview',
      topics: [
        'System boundary and CUI data flows',
        'NIST 800-171 access control implementation',
        'Configuration baseline and change management',
        'Audit logging and monitoring for CUI systems',
        'Continuity and recovery for federal contract systems',
      ],
      questions: [
        {
          text: 'Is this system\'s boundary clearly defined in the SSP — and does the boundary accurately reflect all components, including AI integrations and cloud dependencies?',
          nist: ['MAP 1.1', 'GOVERN 1.2'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'How is user and service account access to CUI within this system granted, reviewed quarterly, and revoked promptly when no longer needed?',
          nist: ['GOVERN 4.1', 'MANAGE 2.2'],
          regs: ['NIST 800-171 §3.1.1', 'FedRAMP AC-2'],
        },
        {
          text: 'Is there a documented and tested configuration baseline for this system — and how are deviations from baseline detected and remediated?',
          nist: ['MANAGE 1.1', 'GOVERN 1.7'],
          regs: ['NIST 800-171 §3.4.1', 'CMMC SI.1.210'],
        },
        {
          text: 'Are audit logs for this system protected from modification, retained for the required period, and reviewed for indicators of insider threat or unauthorised CUI access?',
          nist: ['MEASURE 4.1', 'MANAGE 2.2'],
          regs: ['NIST 800-171 §3.3.1', 'CMMC AC.1.001'],
        },
        {
          text: 'What is the continuity and disaster recovery plan for this system — and does it address scenarios where CUI could be at risk during a disruptive event?',
          nist: ['MANAGE 2.4', 'GOVERN 6.2'],
          regs: ['NIST 800-171 §3.6.1', 'FedRAMP AC-2'],
        },
        {
          text: 'How are critical security patches applied to this system — and is there a documented SLA for CUI-processing systems that aligns with NIST 800-171 requirements?',
          nist: ['MANAGE 1.1', 'GOVERN 1.7'],
          regs: ['NIST 800-171 §3.4.1', 'CMMC SI.1.210'],
        },
      ],
    },
    privacy_officer: {
      roleLabel: 'Privacy Officer',
      domain: 'data_security',
      suggestedTitle: 'Privacy Officer — CMMC/FedRAMP CUI and PII data protection, AI data use interview',
      topics: [
        'CUI categories and PII within AI systems',
        'Data minimisation for CUI processed by AI',
        'Cross-border data flows for AI services handling CUI',
        'Individual rights for PII processed in federal AI systems',
        'DPIA obligations for high-risk federal AI processing',
      ],
      questions: [
        {
          text: 'Which AI systems process CUI that also constitutes Personally Identifiable Information (PII) — and is each identified in both the CUI registry and the organisation\'s PII inventory?',
          nist: ['MEASURE 2.5', 'GOVERN 1.1'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Is there a data minimisation standard that prevents unnecessary CUI or PII from being included in prompts or inputs sent to AI systems?',
          nist: ['MEASURE 2.5', 'MAP 1.5'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
        {
          text: 'Do any AI services used in federal contract performance transfer CUI or PII outside the United States — and if so, how is that authorised and documented?',
          nist: ['GOVERN 4.1', 'MEASURE 2.5'],
          regs: ['NIST 800-171 §3.13.1', 'FedRAMP AC-2'],
        },
        {
          text: 'How are individual rights (access, correction) handled for PII that has been processed by AI systems in the context of federal contract performance?',
          nist: ['MEASURE 2.5', 'GOVERN 1.7'],
          regs: ['NIST 800-171 §3.1.1', 'FedRAMP AC-2'],
        },
        {
          text: 'Has a Privacy Impact Assessment (PIA) been completed for AI systems that process PII in connection with federal contracts — and is it current?',
          nist: ['MAP 5.1', 'MEASURE 2.5'],
          regs: ['NIST 800-171 §3.1.1', 'EO 14110'],
        },
        {
          text: 'What retention and deletion schedule applies to CUI and PII stored in AI interaction logs, model outputs, or inference artefacts — and is it enforced technically?',
          nist: ['GOVERN 1.7', 'MAP 1.5'],
          regs: ['NIST 800-171 §3.1.1', 'CMMC AC.1.001'],
        },
      ],
    },
  },
};

// ── Resolver ─────────────────────────────────────────────────────────────────

/**
 * Returns the most specific InterviewGuide for a given role and assessment type.
 * Falls back to DEFAULT_GUIDES if no sector-specific override exists, and
 * returns null if the role is unknown entirely.
 */
export function getInterviewGuide(
  role: string | undefined,
  assessmentType: string | undefined,
): InterviewGuide | null {
  if (!role) return null;
  const sector: SectorKey =
    (assessmentType ? ASSESSMENT_TYPE_TO_SECTOR[assessmentType] : undefined) ?? 'default';
  return SECTOR_GUIDES[sector]?.[role] ?? DEFAULT_GUIDES[role] ?? null;
}
