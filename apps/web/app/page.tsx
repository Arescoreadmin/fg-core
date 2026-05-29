const FRAMEWORKS = ['NIST AI RMF', 'HIPAA', 'SOC 2', 'CMMC', 'ISO 27001'];

const FEATURES = [
  {
    icon: '⚡',
    title: 'Field Assessment Substrate',
    body:
      'End-to-end engagement management — scan ingestion, evidence collection, playbook execution, and signed report delivery in one platform.',
  },
  {
    icon: '🛡',
    title: 'AI Governance Enforcement',
    body:
      'Map NIST AI RMF controls to your evidence base. Continuous drift detection surfaces compliance gaps before they become audit findings.',
  },
  {
    icon: '📊',
    title: 'Executive Risk Posture',
    body:
      'AI-generated narrative summaries, severity-sorted findings, and a remediation roadmap — client-ready in minutes, not weeks.',
  },
  {
    icon: '🔗',
    title: 'Connector Framework',
    body:
      'Native MS Graph / Azure AD integration with device-code auth. Scan your tenant, pull NIST controls, and ingest findings automatically.',
  },
];

const STEPS = [
  {
    n: '01',
    title: 'Create an Engagement',
    body: 'Spin up a client engagement, assign an assessor, and select your compliance framework.',
  },
  {
    n: '02',
    title: 'Collect Evidence',
    body:
      'Run automated connector scans, complete the NIST questionnaire, and upload supporting documents — all anchored to findings.',
  },
  {
    n: '03',
    title: 'Deliver the Report',
    body:
      'Generate a signed PDF with executive summary, severity findings, remediation roadmap, and framework coverage matrix.',
  },
];

export default function Home() {
  return (
    <>
      {/* Nav */}
      <header className="fixed top-0 inset-x-0 z-50 border-b border-white/10 bg-gray-950/80 backdrop-blur">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <span className="text-sm font-semibold tracking-tight text-white">FrostGate</span>
          <nav className="flex items-center gap-6">
            <a
              href="#features"
              className="hidden sm:block text-sm text-gray-400 hover:text-white transition-colors"
            >
              Features
            </a>
            <a
              href="#how-it-works"
              className="hidden sm:block text-sm text-gray-400 hover:text-white transition-colors"
            >
              How it works
            </a>
            <a
              href="https://console.frostgate.ai"
              className="text-sm text-gray-300 hover:text-white transition-colors"
            >
              Sign in
            </a>
            <a
              href="https://console.frostgate.ai"
              className="text-sm font-medium px-4 py-1.5 rounded-md bg-frost-500 text-white hover:bg-frost-600 transition-colors"
            >
              Get started
            </a>
          </nav>
        </div>
      </header>

      <main>
        {/* Hero */}
        <section className="pt-40 pb-24 px-6">
          <div className="max-w-3xl mx-auto text-center space-y-6">
            <div className="inline-flex items-center gap-2 text-xs font-medium px-3 py-1 rounded-full border border-frost-500/30 bg-frost-500/10 text-frost-300">
              <span className="w-1.5 h-1.5 rounded-full bg-frost-400 animate-pulse" />
              Field Assessment · AI Governance · Compliance
            </div>
            <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-white leading-tight">
              Compliance delivery,{' '}
              <span className="text-frost-400">end-to-end</span>
            </h1>
            <p className="text-lg text-gray-400 max-w-xl mx-auto leading-relaxed">
              FrostGate is the field assessment and AI governance platform for compliance-driven
              organizations. Automate evidence collection, enforce NIST controls, and deliver
              client-ready reports — in one substrate.
            </p>
            <div className="flex flex-wrap gap-3 justify-center pt-2">
              <a
                href="https://console.frostgate.ai"
                className="px-6 py-2.5 rounded-md bg-frost-500 text-white font-medium hover:bg-frost-600 transition-colors"
              >
                Open console
              </a>
              <a
                href="#how-it-works"
                className="px-6 py-2.5 rounded-md border border-white/10 text-gray-300 font-medium hover:border-white/20 hover:text-white transition-colors"
              >
                See how it works
              </a>
            </div>
          </div>

          {/* Framework badges */}
          <div className="max-w-2xl mx-auto mt-16 flex flex-wrap gap-2 justify-center">
            {FRAMEWORKS.map((fw) => (
              <span
                key={fw}
                className="text-xs font-mono px-3 py-1 rounded border border-white/10 bg-white/5 text-gray-400"
              >
                {fw}
              </span>
            ))}
          </div>
        </section>

        {/* Divider */}
        <div className="h-px max-w-6xl mx-auto bg-gradient-to-r from-transparent via-white/10 to-transparent" />

        {/* Features */}
        <section id="features" className="py-24 px-6">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-14 space-y-3">
              <h2 className="text-2xl font-semibold text-white">Everything your team needs</h2>
              <p className="text-gray-400 max-w-lg mx-auto text-sm">
                From first scan to signed report — built for assessors who need speed without
                sacrificing rigor.
              </p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
              {FEATURES.map((f) => (
                <div
                  key={f.title}
                  className="rounded-xl border border-white/10 bg-white/5 p-6 space-y-3 hover:border-frost-500/30 transition-colors"
                >
                  <div className="text-2xl">{f.icon}</div>
                  <h3 className="font-semibold text-white">{f.title}</h3>
                  <p className="text-sm text-gray-400 leading-relaxed">{f.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Divider */}
        <div className="h-px max-w-6xl mx-auto bg-gradient-to-r from-transparent via-white/10 to-transparent" />

        {/* How it works */}
        <section id="how-it-works" className="py-24 px-6">
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-14 space-y-3">
              <h2 className="text-2xl font-semibold text-white">Three steps to delivery</h2>
              <p className="text-gray-400 text-sm">
                A complete assessment lifecycle managed in one place.
              </p>
            </div>
            <div className="space-y-6">
              {STEPS.map((s) => (
                <div
                  key={s.n}
                  className="flex gap-6 rounded-xl border border-white/10 bg-white/5 p-6"
                >
                  <span className="text-3xl font-bold font-mono text-frost-500/40 shrink-0 pt-0.5">
                    {s.n}
                  </span>
                  <div className="space-y-1">
                    <h3 className="font-semibold text-white">{s.title}</h3>
                    <p className="text-sm text-gray-400 leading-relaxed">{s.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="py-24 px-6">
          <div className="max-w-2xl mx-auto text-center rounded-2xl border border-frost-500/20 bg-frost-500/5 px-8 py-16 space-y-6">
            <h2 className="text-2xl font-semibold text-white">
              Ready to run your first assessment?
            </h2>
            <p className="text-gray-400 text-sm max-w-sm mx-auto">
              Get started with FrostGate. No setup required — connect your tenant and begin
              collecting evidence in minutes.
            </p>
            <a
              href="https://console.frostgate.ai"
              className="inline-block px-8 py-3 rounded-md bg-frost-500 text-white font-medium hover:bg-frost-600 transition-colors"
            >
              Open the console
            </a>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 py-8 px-6">
        <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs text-gray-600">
          <span>© {new Date().getFullYear()} FrostGate. All rights reserved.</span>
          <div className="flex gap-6">
            <a href="https://console.frostgate.ai" className="hover:text-gray-400 transition-colors">
              Console
            </a>
            <a href="https://app.frostgate.ai" className="hover:text-gray-400 transition-colors">
              Client Portal
            </a>
          </div>
        </div>
      </footer>
    </>
  );
}
