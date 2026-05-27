'use client';

import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

const FAQS = [
  {
    q: 'Is our assessment data used to train AI models?',
    a: 'No. Your assessment responses are used only to generate your report and are never shared with third parties or used to train any AI model — including the Claude model used for report generation. Your data belongs to you.',
  },
  {
    q: 'Do you sign Business Associate Agreements (BAAs)?',
    a: 'Yes. For healthcare organizations that handle Protected Health Information (PHI), we sign BAAs as part of any engagement. Contact us before starting your assessment so we can execute the BAA first.',
  },
  {
    q: 'How is this different from a generic compliance checklist?',
    a: "Generic checklists ask every organization the same questions regardless of industry, size, or regulatory exposure. FrostGate profiles your organization first — industry, employee count, revenue, PHI/CUI handling, DoD contractor status — and then selects questions from a validated bank tuned to your specific risk surface. A community bank gets FFIEC CAT-weighted questions. A DoD contractor gets CMMC 2.0-weighted questions. A 10-person law firm doesn't get questions built for a 1,000-person enterprise.",
  },
  {
    q: 'What compliance frameworks does the assessment cover?',
    a: 'Coverage depends on your compliance profile. All profiles include NIST AI RMF and CISA Cyber Performance Goals. Regulated profiles (banking, healthcare) add FFIEC CAT, SR 11-7, HIPAA, and HITRUST CSF. GovCon profiles add CMMC 2.0, NIST SP 800-171, DFARS, and FedRAMP. Midmarket and enterprise profiles add SOC 2 and ISO/IEC 27001.',
  },
  {
    q: 'What happens to our data after the assessment?',
    a: 'Assessment responses and generated reports are retained so you can access your report at any time via its unique link. You can request deletion of your data at any time by contacting us. We do not sell, license, or share your assessment data with any third party.',
  },
  {
    q: 'Is the Snapshot a one-time purchase — no ongoing subscription?',
    a: 'Yes. The Snapshot is a single one-time payment ($299, $599, or $999 depending on your profile). There is no recurring charge, no subscription, and no auto-renewal. If you want ongoing monitoring and benchmarking, that is the Intelligence tier ($5,000/year), which you choose separately.',
  },
  {
    q: 'Can we upgrade from Snapshot to Intelligence after our assessment?',
    a: 'Yes. Your assessment data carries forward. When you upgrade to Intelligence, your existing risk scores become the baseline for trend tracking — you do not start over.',
  },
  {
    q: 'What if the report does not meet our expectations?',
    a: 'Contact us within 7 days of receiving your report. If the content does not reflect your assessment responses accurately, we will regenerate the report at no charge. If you are still not satisfied, we offer a full refund.',
  },
];

export function FaqSection() {
  const [open, setOpen] = useState<number | null>(null);

  return (
    <div className="space-y-2">
      {FAQS.map((faq, i) => (
        <div
          key={i}
          className="rounded-lg border border-border bg-surface-2 overflow-hidden"
        >
          <button
            className="w-full flex items-center justify-between px-5 py-4 text-left gap-4 hover:bg-surface-3 transition-colors"
            onClick={() => setOpen(open === i ? null : i)}
            aria-expanded={open === i}
          >
            <span className="text-sm font-medium text-foreground">{faq.q}</span>
            <ChevronDown
              className={`h-4 w-4 text-muted shrink-0 transition-transform duration-200 ${
                open === i ? 'rotate-180' : ''
              }`}
            />
          </button>
          {open === i && (
            <div className="px-5 pb-5 animate-fade-in">
              <p className="text-sm text-muted leading-relaxed">{faq.a}</p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
