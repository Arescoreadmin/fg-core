# Discovery Call Script
## 30-Minute Qualification Call

**Purpose:** Qualify the prospect, understand their environment and buying trigger, deliver the FrostGate pitch at the right moment, and secure a next step.

**NOT the purpose:** Close on this call. The goal is a scheduled data collection session and signed SOW — not verbal commitment.

---

## Pre-Call Prep (5 minutes)

Before the call:
- Review the prospect's LinkedIn (size, industry, any AI or compliance news)
- Look up their domain on Shodan and check DNS/email security quickly — if you find obvious issues (no DMARC, no SPF), have them ready as a concrete hook
- Know whether they are likely HIPAA, SOC 2, CMMC, or another framework
- Have the one-page overview ready to share by email after the call

---

## Section 1 — Introduction (2 minutes)

"Thanks for making time. I want to make this useful for you in 30 minutes regardless of whether we work together. Here's what I'd like to do: spend the first 10 minutes understanding your situation, then give you a 5-minute overview of what FrostGate does, then figure out together whether this is a fit and what a next step looks like. Does that work?"

[Wait for confirmation.]

---

## Section 2 — Prospect Context Questions (10 minutes)

Ask in order. Do not interrupt. Take notes.

**Opening:**
"What brought you to look at AI governance now — was there a specific event, or has it been building?"

*Listen for: board question, audit prep, new employee policy, vendor requirement, incident, or just 'we started using Copilot and realized we have no idea what it's doing.'*

**Org and AI tooling:**
"What AI tools are you actively using — Copilot, ChatGPT, anything custom?"

"How many people are using AI tools day-to-day?"

**Ownership:**
"Who owns the AI governance question at your organization right now — is there a CISO, a compliance officer, or is it you?"

**Azure environment (qualification gate):**
"Are you a Microsoft 365 shop? Do you use Azure Active Directory or Entra ID for identity?"

*If NO: This is a hard disqualifier. See disqualifiers section below.*

**Regulatory context:**
"What compliance frameworks are you subject to or working toward — HIPAA, SOC 2, CMMC, ISO 27001?"

**Pain:**
"Has a board member, auditor, or regulator asked about AI governance yet? Or is this proactive?"

**Timeline:**
"Is there a deadline driving this, or is this more 'we should get this done soon'?"

*Note: If deadline is inside 30 days with an active exam underway — see disqualifiers.*

---

## Section 3 — FrostGate Overview Pitch (8 minutes)

"Let me tell you what we do, and you can tell me whether it fits your situation."

**What we do (2 minutes):**
"FrostGate runs a structured field assessment of how your organization is using AI tools — what they can access, what policies govern them, and what a regulator or auditor would say. We connect directly to your Microsoft 365 environment, review your public infrastructure, and produce a written report with specific findings, a risk score, and a prioritized action plan. It's assessor-led — I'm on the call with your team, we do the technical work together, and I explain what we're finding in real time."

**How it works (3 minutes):**
"The engagement has three phases. First, before the meeting, I run three passive scans against your domain and public URLs — DNS and email security, web security headers, and network exposure. These require nothing from you.

Then we have a single 75-to-90-minute working session where I authenticate into your Microsoft 365 environment using a device-code flow — your administrator enters a code, we get read-only access, and I run 10 connectors: identity and MFA, conditional access policies, devices, SharePoint exposure, OAuth and AI tool inventory, and more. At the same time, we walk through a 69-control questionnaire aligned to the NIST AI Risk Management Framework.

After the session, I compile the report, QA-review it, and within 5 to 7 business days, you have access to a secure portal with your findings, a risk dashboard, a remediation roadmap, and a downloadable PDF report."

**What you get (2 minutes):**
"What you end up with is a defensible record of your AI governance posture — specific findings, the evidence behind them, and the actions to close the gaps — in a format you can share with executives, your board, or a regulator. It's not a questionnaire PDF; it's a living portal where you can track remediation over time. At 30 days, I come back and re-scan to show you what changed."

**Price:**
"The standard rate is $5,000 for a fixed scope. For early clients who are willing to give me feedback and potentially serve as a reference, I offer a design partner rate of $2,500. Either way, the scope is identical."

---

## Section 4 — Logistics and Scope Questions (5 minutes)

"Let me ask a few quick questions to make sure this is technically feasible for you."

**Entra ID confirmation (if not already confirmed):**
"You confirmed you're on Microsoft 365 — do you have a Global Administrator or Application Administrator who can be on a call with us for the first 30 minutes of the session? They need to enter a device code to authorize our read-only access."

**Domain and URLs:**
"What's your primary domain and do you have a public-facing website?"

**Timing:**
"How quickly would you want to do this? The setup requires scheduling about a week out — there's a 30-minute Azure app registration step that your IT person needs to complete before the session."

**Decision process:**
"If this makes sense, is this something you can move on, or are there other stakeholders who need to weigh in?"

---

## Section 5 — Close (5 minutes)

**If strong fit:**
"Based on what you've told me, this sounds like a good fit. Here's what I'd suggest: I'll send you the one-page overview and a proposal with the full scope and terms today. If that looks right, we can schedule a call to review the SOW and pick a date. The goal would be to get the data collection session on the calendar in the next two to three weeks. Does that work?"

**If uncertain fit:**
"I want to make sure this is the right investment for you. Let me send you the one-page overview so you can review it before we decide on next steps. What would need to be true for this to be the right timing?"

**If disqualified:**
"Based on what you've told me, [specific reason — no Entra ID / active exam / procurement cycle too long], this probably isn't the right fit right now. [Specific resolution if applicable — 'Once your exam is closed, give me a call. This is exactly what you'd want to do in the 90-day window after.']. I'd rather tell you that now than waste your time."

**Next step commitment:**
"Can I send you the one-page overview today? And if that looks right, can we agree on a time this week or next to review the terms?"

---

## Disqualifiers — Decline Politely

| Disqualifier | What to say |
|--------------|-------------|
| No Azure AD / Entra ID | "Ten of our thirteen connectors run against Microsoft 365 and Entra ID — without that, the assessment loses most of its value. This isn't the right fit for your environment today. If that changes, give me a call." |
| No internal AI tool deployment | "Our assessment is designed for organizations already using AI tools — there needs to be something to assess. If you're just starting to adopt AI, the right sequence might be to get a governance policy in place first, then assess once you have tools in use." |
| Active audit or regulatory exam underway | "We're a great fit for the 90-day window after your exam closes — that's when you have the pressure and the clarity to actually act on the findings. I wouldn't want to run an assessment during an active exam when your team has no bandwidth for it." |
| Procurement cycle over 60 days | "Our engagement model is built for fast-moving organizations — if your procurement cycle is over 60 days, I'm not going to be able to work within that for a first engagement. Let's stay in touch for when the timing is better." |
| Requires vendor SOC 2 from FrostGate | "We don't have a vendor SOC 2 yet — that's a Stage 2 deliverable. If your vendor risk program requires it, this engagement probably won't fit your requirements right now." |

---

## Key Pitch Points (plain English, no jargon)

| Technical capability | What to say to a buyer |
|---------------------|------------------------|
| 13 connectors | "We run thirteen different automated checks against your environment — your domain, your website, your email security records, and ten different views into your Microsoft 365 — so you get a comprehensive picture, not just a questionnaire." |
| NIST AI RMF | "We evaluate your posture against the NIST AI Risk Management Framework, which is the emerging federal standard for AI governance. It gives you a structured way to tell a regulator 'here's how we manage AI risk.'" |
| Evidence chain | "Every finding comes with the evidence behind it — what we found, when we found it, and what it means. It's not a questionnaire response; it's a documented record." |
| QA process | "Before we deliver anything, I review and approve the report myself. What goes to you has been reviewed for accuracy and plain-language clarity." |
| Living portal | "You don't get a PDF and a handshake. You get a portal where you can track remediation, mark findings resolved, and see your posture improve over time." |
| 30-day check-in | "At 30 days, I come back and re-run the passive scans to show you what changed. For most clients, that's the first time they can say 'we fixed something' with evidence." |

---

## Do NOT Promise

- Automated continuous monitoring (not in scope for OFFER A)
- Real-time alerts
- Vault-signed reports until confirmed (say: "the PDF report is delivered with an integrity record; we'll confirm the specific signing mechanism at kickoff")
- SOC 2 for FrostGate
- SAML or SSO for the portal
- Results within 24 hours (5–7 business days is the commitment)
- Penetration testing or active exploitation

---

## After the Call

Within 2 hours:
- Send the one-page overview (`docs/commercial/one_page_overview.md`)
- Send the proposal if qualified (`docs/commercial/proposal_template.md`)
- Record the call outcome and any notes in the engagement log
- If disqualified, record why and when to follow up (if ever)

If no response in 7 days:
"Hi [NAME] — following up on our call. Happy to answer any questions about the assessment scope or timing. Is this still on your radar for [MONTH]?"
