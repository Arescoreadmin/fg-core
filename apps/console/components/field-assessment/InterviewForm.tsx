'use client';

/**
 * InterviewForm — captures structured interview records as field observations.
 *
 * Backend mapping: POSTs to POST /observations with observation_type="interview"
 * and interview_role required. Interviews are NOT a separate entity — they are
 * FaFieldObservation records with interview_role populated. This is intentional:
 * interviews produce structured governance evidence in the same lineage as
 * technical observations. See docs/ai/PR_FIX_LOG.md PR 2 entry.
 */

import { useEffect, useRef, useState } from 'react';
import { Button, Input, Label, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@fg/ui';
import { Textarea } from '@fg/ui';
import { Alert, AlertDescription } from '@fg/ui';
import { fieldAssessmentApi, type ObservationDomain, type ObservationSeverity, type Observation } from '@/lib/fieldAssessmentApi';

const DOMAINS: { value: ObservationDomain; label: string }[] = [
  { value: 'ai_governance', label: 'AI Governance' },
  { value: 'data_security', label: 'Data Security' },
  { value: 'access_management', label: 'Access Management' },
  { value: 'operational_security', label: 'Operational Security' },
  { value: 'compliance', label: 'Compliance' },
  { value: 'vendor_management', label: 'Vendor Management' },
  { value: 'incident_response', label: 'Incident Response' },
  { value: 'training', label: 'Training' },
];

const CONFIDENCE_OPTIONS = [
  { value: 'high', label: 'High — subject was direct, evidence corroborated' },
  { value: 'medium', label: 'Medium — subject was uncertain or partial evidence' },
  { value: 'low', label: 'Low — anecdotal, unverified, or contradicted' },
];

interface InterviewQuestion {
  text: string;
  nist: string[]; // NIST AI RMF 1.0 subcategory references
}

interface InterviewGuide {
  roleLabel: string;
  domain: ObservationDomain;
  suggestedTitle: string;
  topics: string[];
  questions: InterviewQuestion[];
}

const INTERVIEW_GUIDES: Record<string, InterviewGuide> = {
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

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60).toString().padStart(2, '0');
  const s = (seconds % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

async function hashBlob(blob: Blob): Promise<string> {
  const buf = await blob.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

type RecordingState = 'idle' | 'recording' | 'paused' | 'stopped';

function RecordingWidget({
  onAudioReady,
  onUseTranscript,
}: {
  onAudioReady: (info: { hash: string; sizeKb: number; durationSec: number; blobUrl: string; blob: Blob }) => void;
  onUseTranscript: (text: string) => void;
}) {
  const [recState, setRecState] = useState<RecordingState>('idle');
  const [displayTime, setDisplayTime] = useState(0);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [audioInfo, setAudioInfo] = useState<{ hash: string; sizeKb: number; durationSec: number } | null>(null);
  const [recError, setRecError] = useState<string | null>(null);
  const [transcript, setTranscript] = useState<string | null>(null);
  const [transcribing, setTranscribing] = useState(false);
  const [transcriptError, setTranscriptError] = useState<string | null>(null);
  const blobRef = useRef<Blob | null>(null);

  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const elapsedRef = useRef(0);     // total elapsed seconds at last pause
  const startedAtRef = useRef(0);   // Date.now() when last resumed

  function tick() {
    const total = elapsedRef.current + Math.floor((Date.now() - startedAtRef.current) / 1000);
    setDisplayTime(total);
  }

  function startTimer() {
    startedAtRef.current = Date.now();
    timerRef.current = setInterval(tick, 1000);
  }

  function stopTimer() {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    elapsedRef.current += Math.floor((Date.now() - startedAtRef.current) / 1000);
  }

  async function start() {
    setRecError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      chunksRef.current = [];
      elapsedRef.current = 0;
      setDisplayTime(0);

      const recorder = new MediaRecorder(stream);
      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunksRef.current.push(e.data);
      };
      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(chunksRef.current, { type: recorder.mimeType || 'audio/webm' });
        const url = URL.createObjectURL(blob);
        const hash = await hashBlob(blob);
        const info = {
          hash,
          sizeKb: Math.round(blob.size / 1024),
          durationSec: elapsedRef.current,
          blobUrl: url,
          blob,
        };
        blobRef.current = blob;
        setBlobUrl(url);
        setTranscript(null);
        setTranscriptError(null);
        setAudioInfo({ hash, sizeKb: info.sizeKb, durationSec: info.durationSec });
        onAudioReady(info);
        setRecState('stopped');
      };

      recorder.start(500);
      mediaRecorderRef.current = recorder;
      setRecState('recording');
      startTimer();
    } catch {
      setRecError('Microphone access denied — check browser permissions.');
    }
  }

  function pause() {
    mediaRecorderRef.current?.pause();
    stopTimer();
    setRecState('paused');
  }

  function resume() {
    mediaRecorderRef.current?.resume();
    startTimer();
    setRecState('recording');
  }

  function stop() {
    stopTimer();
    mediaRecorderRef.current?.stop();
    // onstop handler fires async and sets state to 'stopped'
  }

  async function transcribe() {
    if (!blobRef.current) return;
    setTranscribing(true);
    setTranscriptError(null);
    setTranscript(null);
    try {
      const form = new FormData();
      form.append('audio', blobRef.current, 'interview.webm');
      const res = await fetch('/api/field-assessment/transcribe', { method: 'POST', body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Transcription failed');
      setTranscript(data.text as string);
    } catch (e) {
      setTranscriptError(e instanceof Error ? e.message : 'Transcription failed');
    } finally {
      setTranscribing(false);
    }
  }

  function discard() {
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    blobRef.current = null;
    setBlobUrl(null);
    setAudioInfo(null);
    setDisplayTime(0);
    setTranscript(null);
    setTranscriptError(null);
    elapsedRef.current = 0;
    setRecState('idle');
    onAudioReady({ hash: '', sizeKb: 0, durationSec: 0, blobUrl: '', blob: new Blob() });
  }

  function download() {
    if (!blobUrl) return;
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `interview-recording-${Date.now()}.webm`;
    a.click();
  }

  // Cleanup blob URL on unmount
  useEffect(() => {
    return () => {
      if (blobUrl) URL.revokeObjectURL(blobUrl);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [blobUrl]);

  return (
    <div className="rounded border border-border bg-surface-2 p-3 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-foreground">Audio recording</p>
        <div className="flex items-center gap-2">
          {recState === 'recording' && (
            <span className="flex items-center gap-1 text-[11px] text-red-300">
              <span className="inline-block h-2 w-2 rounded-full bg-red-400 animate-pulse" />
              REC
            </span>
          )}
          {recState === 'paused' && (
            <span className="text-[11px] text-amber-300">PAUSED</span>
          )}
          <span className="font-mono text-xs text-foreground tabular-nums">
            {formatDuration(displayTime)}
          </span>
        </div>
      </div>

      {recState === 'idle' && (
        <button
          type="button"
          onClick={start}
          className="flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-200 transition hover:bg-red-500/20 focus:outline-none focus:ring-2 focus:ring-red-500/40"
        >
          <span className="inline-block h-2 w-2 rounded-full bg-red-400" />
          Start recording
        </button>
      )}

      {(recState === 'recording' || recState === 'paused') && (
        <div className="flex items-center gap-2">
          {recState === 'recording' ? (
            <button
              type="button"
              onClick={pause}
              className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-200 transition hover:bg-amber-500/20 focus:outline-none focus:ring-2 focus:ring-amber-500/40"
            >
              ⏸ Pause
            </button>
          ) : (
            <button
              type="button"
              onClick={resume}
              className="flex items-center gap-2 rounded border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-200 transition hover:bg-red-500/20 focus:outline-none focus:ring-2 focus:ring-red-500/40"
            >
              <span className="inline-block h-2 w-2 rounded-full bg-red-400" />
              Resume
            </button>
          )}
          <button
            type="button"
            onClick={stop}
            className="rounded border border-border bg-surface-1 px-3 py-1.5 text-xs font-medium text-foreground transition hover:border-primary/50 focus:outline-none focus:ring-2 focus:ring-primary/40"
          >
            ⏹ Stop
          </button>
        </div>
      )}

      {recState === 'stopped' && blobUrl && audioInfo && (
        <div className="space-y-2">
          <audio controls src={blobUrl} className="w-full h-8" />
          <div className="flex items-center justify-between text-[11px] text-muted">
            <span>{formatDuration(audioInfo.durationSec)} · {audioInfo.sizeKb} KB</span>
            <span className="font-mono truncate max-w-[160px]" title={audioInfo.hash}>
              SHA-256: {audioInfo.hash.slice(0, 12)}…
            </span>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={download}
              className="rounded border border-border bg-surface-1 px-2 py-1 text-[11px] text-foreground transition hover:border-primary/50 focus:outline-none"
            >
              Download
            </button>
            <button
              type="button"
              onClick={discard}
              className="rounded border border-border px-2 py-1 text-[11px] text-muted transition hover:text-foreground focus:outline-none"
            >
              Discard
            </button>
          </div>

          {/* Transcription panel */}
          {!transcript && !transcribing && (
            <button
              type="button"
              onClick={transcribe}
              className="w-full rounded border border-primary/30 bg-primary/10 px-3 py-2 text-xs font-medium text-primary transition hover:bg-primary/20 focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              Transcribe with Whisper (~$0.006 / min)
            </button>
          )}

          {transcribing && (
            <div className="flex items-center gap-2 rounded border border-border bg-surface-1 px-3 py-2">
              <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              <span className="text-xs text-muted">Transcribing — this may take a moment…</span>
            </div>
          )}

          {transcript && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-[11px] font-medium text-muted uppercase tracking-wide">Transcript</p>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => onUseTranscript(transcript)}
                    className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-200 transition hover:bg-emerald-500/20 focus:outline-none"
                  >
                    Use as notes
                  </button>
                  <button
                    type="button"
                    onClick={transcribe}
                    className="rounded border border-border px-2 py-0.5 text-[11px] text-muted transition hover:text-foreground focus:outline-none"
                  >
                    Re-transcribe
                  </button>
                </div>
              </div>
              <div className="max-h-48 overflow-y-auto rounded border border-border bg-surface-1 p-2 text-xs text-foreground whitespace-pre-wrap leading-relaxed">
                {transcript}
              </div>
            </div>
          )}

          {transcriptError && (
            <p className="text-[11px] text-red-300">{transcriptError}</p>
          )}
        </div>
      )}

      {recError && (
        <p className="text-[11px] text-red-300">{recError}</p>
      )}
      <p className="text-[11px] text-muted">
        Recording stays in your browser — download to keep a local copy. The SHA-256 hash is attached to the observation as a tamper-evident artifact reference.
      </p>
    </div>
  );
}

interface InterviewPrefill {
  role?: string;
  title?: string;
  instruction?: string;
}

interface Props {
  engagementId: string;
  prefill?: InterviewPrefill | null;
  onSuccess: (obs: Observation) => void;
}

export function InterviewForm({ engagementId, prefill, onSuccess }: Props) {
  const [interviewRole, setInterviewRole] = useState('');
  const [businessFunction, setBusinessFunction] = useState('');
  const [domain, setDomain] = useState<ObservationDomain | ''>('');
  const [severity, setSeverity] = useState<ObservationSeverity | ''>('');
  const [title, setTitle] = useState('');
  const [aiUsageAsserted, setAiUsageAsserted] = useState('');
  const [policyAwareness, setPolicyAwareness] = useState('');
  const [structuredNotes, setStructuredNotes] = useState('');
  const [confidence, setConfidence] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastObs, setLastObs] = useState<Observation | null>(null);
  const [guideOpen, setGuideOpen] = useState(true);
  const [audioArtifact, setAudioArtifact] = useState<{ hash: string; sizeKb: number; durationSec: number } | null>(null);

  const guide = prefill?.role ? INTERVIEW_GUIDES[prefill.role] ?? null : null;

  // Unique NIST AI RMF refs across all questions in the guide, sorted.
  const nistRefs = guide
    ? Array.from(new Set(guide.questions.flatMap((q) => q.nist))).sort()
    : [];

  useEffect(() => {
    if (!prefill) return;
    if (guide) {
      setInterviewRole(guide.roleLabel);
      setDomain(guide.domain);
      setTitle(guide.suggestedTitle);
    } else if (prefill.role) {
      setInterviewRole(prefill.role.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()));
    }
    setGuideOpen(true);
  }, [prefill]); // eslint-disable-line react-hooks/exhaustive-deps

  const canSubmit =
    interviewRole.trim() !== '' &&
    domain !== '' &&
    severity !== '' &&
    title.trim() !== '' &&
    structuredNotes.trim() !== '' &&
    !submitting;

  async function handleSubmit() {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);

    const audioLine = audioArtifact?.hash
      ? `\n\n[Audio artifact: ${audioArtifact.durationSec}s, ${audioArtifact.sizeKb} KB, SHA-256: ${audioArtifact.hash}]`
      : '';
    const nistLine = nistRefs.length > 0
      ? `\n\n[NIST AI RMF: ${nistRefs.join(', ')}]`
      : '';

    const description = [
      businessFunction.trim() && `Business function: ${businessFunction.trim()}`,
      aiUsageAsserted.trim() && `AI usage asserted: ${aiUsageAsserted.trim()}`,
      policyAwareness.trim() && `Policy awareness: ${policyAwareness.trim()}`,
      confidence && `Confidence: ${confidence}`,
      structuredNotes.trim(),
    ]
      .filter(Boolean)
      .join('\n\n') + nistLine + audioLine;

    try {
      const obs = await fieldAssessmentApi.captureObservation(engagementId, {
        domain: domain as ObservationDomain,
        observation_type: 'interview',
        severity: severity as ObservationSeverity,
        title: title.trim(),
        description,
        interview_role: interviewRole.trim(),
      });
      setLastObs(obs);
      setInterviewRole('');
      setBusinessFunction('');
      setDomain('');
      setSeverity('');
      setTitle('');
      setAiUsageAsserted('');
      setPolicyAwareness('');
      setStructuredNotes('');
      setConfidence('');
      setAudioArtifact(null);
      onSuccess(obs);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Capture failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4" aria-label="interview-form">
      {/* Interview guide — shown when a prefill is active */}
      {prefill && (
        <div className="rounded border border-primary/30 bg-primary/5">
          <button
            type="button"
            className="flex w-full items-center justify-between px-3 py-2 text-left focus:outline-none"
            onClick={() => setGuideOpen((v) => !v)}
            aria-expanded={guideOpen}
          >
            <div>
              <p className="text-xs font-semibold text-foreground">
                Interview guide — {guide?.roleLabel ?? prefill.role?.replace(/_/g, ' ')}
              </p>
              {prefill.instruction && (
                <p className="text-[11px] text-muted mt-0.5">{prefill.instruction}</p>
              )}
            </div>
            <span className="text-xs text-muted shrink-0 ml-2">{guideOpen ? '▲ collapse' : '▼ expand'}</span>
          </button>

          {guideOpen && guide && (
            <div className="border-t border-primary/20 px-3 pb-3 pt-2 space-y-3">
              <div>
                <p className="text-[11px] font-medium text-muted uppercase tracking-wide mb-1">Key topics to cover</p>
                <ul className="space-y-0.5">
                  {guide.topics.map((topic) => (
                    <li key={topic} className="flex items-start gap-1.5 text-xs text-foreground">
                      <span className="mt-0.5 shrink-0 text-primary">•</span>
                      {topic}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <p className="text-[11px] font-medium text-muted uppercase tracking-wide mb-1">Suggested questions</p>
                <ol className="space-y-2 list-none">
                  {guide.questions.map((q, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-foreground">
                      <span className="shrink-0 text-[10px] text-muted font-mono mt-0.5 w-4 text-right">{i + 1}.</span>
                      <div className="space-y-0.5">
                        <span>{q.text}</span>
                        {q.nist.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {q.nist.map((ref) => (
                              <span key={ref} className="inline-flex items-center rounded px-1 py-0.5 text-[10px] font-mono border border-primary/20 bg-primary/10 text-primary">
                                {ref}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recording widget */}
      <RecordingWidget
        onAudioReady={(info) => {
          if (info.hash) {
            setAudioArtifact({ hash: info.hash, sizeKb: info.sizeKb, durationSec: info.durationSec });
          } else {
            setAudioArtifact(null);
          }
        }}
        onUseTranscript={(text) =>
          setStructuredNotes((prev) => (prev.trim() ? `${prev.trim()}\n\n${text}` : text))
        }
      />

      <div className="rounded border border-info/20 bg-info/5 px-3 py-2 text-xs text-info">
        Interview records are stored as structured field observations (type: interview) anchored to this engagement.
        Capture role — not personal name. Avoid PII beyond what governance evidence requires.
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="int-role">Interviewee Role / Title *</Label>
          <Input
            id="int-role"
            aria-required="true"
            placeholder="e.g., CTO, CISO, Data Steward"
            value={interviewRole}
            onChange={(e) => setInterviewRole(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-function">Business Function</Label>
          <Input
            id="int-function"
            placeholder="e.g., Engineering, Legal, Operations"
            value={businessFunction}
            onChange={(e) => setBusinessFunction(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-domain">Domain *</Label>
          <Select value={domain} onValueChange={(v) => setDomain(v as ObservationDomain)}>
            <SelectTrigger id="int-domain" aria-required="true">
              <SelectValue placeholder="Select domain…" />
            </SelectTrigger>
            <SelectContent>
              {DOMAINS.map((d) => (
                <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-severity">Governance Severity *</Label>
          <Select value={severity} onValueChange={(v) => setSeverity(v as ObservationSeverity)}>
            <SelectTrigger id="int-severity" aria-required="true">
              <SelectValue placeholder="Select severity…" />
            </SelectTrigger>
            <SelectContent>
              {(['critical', 'high', 'medium', 'low', 'info'] as ObservationSeverity[]).map((s) => (
                <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-title">Interview Summary Title *</Label>
        <Input
          id="int-title"
          aria-required="true"
          placeholder="e.g., CTO interview — AI adoption awareness"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="int-ai-usage">AI Usage Asserted</Label>
          <Input
            id="int-ai-usage"
            placeholder="e.g., Uses ChatGPT for draft communications"
            value={aiUsageAsserted}
            onChange={(e) => setAiUsageAsserted(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="int-policy">Policy Awareness</Label>
          <Input
            id="int-policy"
            placeholder="e.g., Aware of AI policy, did not read it"
            value={policyAwareness}
            onChange={(e) => setPolicyAwareness(e.target.value)}
          />
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-notes">Structured Notes *</Label>
        <Textarea
          id="int-notes"
          aria-required="true"
          placeholder="Key responses, evidence references, governance observations from this interview"
          className="min-h-[120px]"
          value={structuredNotes}
          onChange={(e) => setStructuredNotes(e.target.value)}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="int-confidence">Confidence Level</Label>
        <Select value={confidence} onValueChange={setConfidence}>
          <SelectTrigger id="int-confidence">
            <SelectValue placeholder="Select confidence…" />
          </SelectTrigger>
          <SelectContent>
            {CONFIDENCE_OPTIONS.map((c) => (
              <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {audioArtifact && (
        <div className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-100">
          Audio artifact will be attached — {formatDuration(audioArtifact.durationSec)}, {audioArtifact.sizeKb} KB, hash {audioArtifact.hash.slice(0, 12)}…
        </div>
      )}

      {lastObs && (
        <Alert variant="success">
          <AlertDescription>Interview captured: <span className="font-medium">{lastObs.title}</span></AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Button onClick={handleSubmit} disabled={!canSubmit} aria-label="Record interview">
        {submitting ? 'Recording…' : 'Record Interview'}
      </Button>
    </div>
  );
}
