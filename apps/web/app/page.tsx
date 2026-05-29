const METRICS = [
  { value: '69',   label: 'NIST AI RMF Controls' },
  { value: '5',    label: 'Compliance Frameworks' },
  { value: '100%', label: 'Cryptographic Evidence Chain' },
  { value: 'EOL',  label: 'Vendor Lock-in' },
];

const CAPABILITIES = [
  {
    index: '01',
    label: 'FIELD ASSESSMENT',
    title: 'End-to-end engagement substrate',
    lines: [
      'Scan ingestion & evidence anchoring',
      'Cryptographically signed PDF reports',
      'Finding lifecycle with closed-loop resolution',
    ],
  },
  {
    index: '02',
    label: 'AI GOVERNANCE',
    title: 'NIST AI RMF enforcement',
    lines: [
      '69-control structured questionnaire',
      'Continuous drift detection & delta alerts',
      'Per-control coverage matrix',
    ],
  },
  {
    index: '03',
    label: 'CONNECTOR PLATFORM',
    title: 'Automated evidence ingestion',
    lines: [
      'MS Graph / Azure AD native integration',
      'Device-code auth — no credentials stored',
      'Multi-framework scan dispatch',
    ],
  },
  {
    index: '04',
    label: 'CLIENT PORTAL',
    title: 'Risk intelligence delivery',
    lines: [
      'Executive risk posture dashboard',
      'Phased remediation roadmap',
      'Attestation workflow & compliance delta',
    ],
  },
];

const FRAMEWORKS = ['NIST AI RMF', 'HIPAA', 'SOC 2', 'CMMC', 'ISO 27001'];

export default function Home() {
  return (
    <>
      {/* ── NAVIGATION ─────────────────────────────────────────────── */}
      <header className="fixed top-0 inset-x-0 z-50 border-b border-[#1c1c1c] bg-[#080808]/90 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="font-display text-lg font-semibold tracking-widest text-[#d0d0d0] uppercase">
              FrostGate
            </span>
          </div>
          <nav className="flex items-center gap-8">
            <a href="#capabilities" className="hidden md:block text-xs tracking-[0.14em] uppercase text-[#666] hover:text-[#c0c0c0] transition-colors">
              Capabilities
            </a>
            <a href="#mission" className="hidden md:block text-xs tracking-[0.14em] uppercase text-[#666] hover:text-[#c0c0c0] transition-colors">
              Mission
            </a>
            <a href="https://console.frostgate.ai" className="hidden md:block text-xs tracking-[0.14em] uppercase text-[#666] hover:text-[#c0c0c0] transition-colors">
              Sign In
            </a>
            <a
              href="https://console.frostgate.ai"
              className="text-xs tracking-[0.14em] uppercase font-medium px-5 py-2 border border-[#3a3a3a] text-[#c0c0c0] hover:border-[#606060] hover:text-white transition-colors"
            >
              Console →
            </a>
          </nav>
        </div>
      </header>

      <main>
        {/* ── HERO ──────────────────────────────────────────────────── */}
        <section className="relative min-h-screen flex flex-col justify-center overflow-hidden px-8 pt-16">
          {/* Faint horizontal grid lines */}
          <div className="absolute inset-0 pointer-events-none" aria-hidden="true">
            {[25, 50, 75].map((pct) => (
              <div
                key={pct}
                className="absolute inset-x-0 border-t border-white/[0.025]"
                style={{ top: `${pct}%` }}
              />
            ))}
          </div>

          <div className="relative max-w-7xl mx-auto w-full">
            <p className="text-xs tracking-[0.22em] uppercase text-steel-400 mb-6 font-medium">
              Field Assessment · AI Governance · Compliance
            </p>

            <h1
              className="font-display font-bold uppercase leading-none tracking-tight text-white"
              style={{ fontSize: 'clamp(56px, 9vw, 112px)' }}
            >
              Field<br />Assessment<br />
              <span className="text-[#2e2e2e]">Redefined.</span>
            </h1>

            <div className="my-10 w-24 h-px bg-steel-500" />

            <p className="text-[#666] text-lg font-light max-w-xl leading-relaxed">
              AI-governed compliance delivery for organizations that cannot afford to fail.
              One platform from first scan to signed report.
            </p>

            <div className="mt-12 flex flex-wrap gap-4">
              <a
                href="https://console.frostgate.ai"
                className="px-8 py-3.5 bg-white text-black text-sm tracking-[0.10em] uppercase font-semibold hover:bg-[#d4d4d4] transition-colors"
              >
                Access Console
              </a>
              <a
                href="#capabilities"
                className="px-8 py-3.5 border border-[#2a2a2a] text-[#666] text-sm tracking-[0.10em] uppercase font-medium hover:border-[#444] hover:text-[#aaa] transition-colors"
              >
                View Capabilities ↓
              </a>
            </div>

            <div className="mt-16 flex flex-wrap gap-x-8 gap-y-2">
              {FRAMEWORKS.map((fw) => (
                <span key={fw} className="text-xs tracking-[0.14em] uppercase text-[#303030] font-mono">
                  {fw}
                </span>
              ))}
            </div>
          </div>
        </section>

        {/* ── METRICS BAND ─────────────────────────────────────────── */}
        <div className="border-y border-[#1c1c1c] bg-[#0f0f0f]">
          <div className="max-w-7xl mx-auto px-8 py-14 grid grid-cols-2 md:grid-cols-4 gap-10 md:gap-0 md:divide-x md:divide-[#1c1c1c]">
            {METRICS.map((m) => (
              <div key={m.label} className="md:px-10 first:pl-0 last:pr-0">
                <p className="font-display text-5xl font-bold text-white tracking-tight">{m.value}</p>
                <p className="mt-2 text-[10px] tracking-[0.16em] uppercase text-[#444]">{m.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* ── CAPABILITIES ─────────────────────────────────────────── */}
        <section id="capabilities" className="py-32 px-8">
          <div className="max-w-7xl mx-auto">
            <div className="mb-16 flex items-end justify-between gap-8 border-b border-[#1c1c1c] pb-8">
              <h2 className="font-display text-4xl font-bold uppercase tracking-tight text-white">
                Platform Capabilities
              </h2>
              <p className="text-[#444] text-sm max-w-xs text-right hidden md:block leading-relaxed">
                Every component purpose-built for compliance delivery at enterprise scale.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 border border-[#1c1c1c] divide-y md:divide-y-0 divide-[#1c1c1c]">
              {CAPABILITIES.map((c, i) => (
                <div
                  key={c.index}
                  className={`p-10 hover:bg-[#0f0f0f] transition-colors${i < 2 ? ' md:border-b border-[#1c1c1c]' : ''}${i % 2 === 0 ? ' md:border-r border-[#1c1c1c]' : ''}`}
                >
                  <div className="flex items-start gap-6">
                    <span className="font-display text-5xl font-bold text-[#191919] leading-none shrink-0 select-none">
                      {c.index}
                    </span>
                    <div>
                      <p className="text-[10px] tracking-[0.22em] uppercase text-steel-400 mb-2 font-medium">
                        {c.label}
                      </p>
                      <h3 className="text-white font-medium text-base mb-5 leading-snug">{c.title}</h3>
                      <ul className="space-y-2.5">
                        {c.lines.map((line) => (
                          <li key={line} className="text-[#484848] text-sm flex items-start gap-2.5">
                            <span className="text-[#2a2a2a] mt-px shrink-0 font-mono">—</span>
                            {line}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── MISSION ──────────────────────────────────────────────── */}
        <section id="mission" className="py-40 px-8 border-y border-[#1c1c1c] relative overflow-hidden">
          <div className="relative max-w-7xl mx-auto text-center">
            <p className="text-[10px] tracking-[0.26em] uppercase text-[#333] mb-8">Mission</p>
            <h2
              className="font-display font-bold uppercase text-white leading-none tracking-tight"
              style={{ fontSize: 'clamp(48px, 7vw, 96px)' }}
            >
              Trust But Verify.
            </h2>
            <div className="mx-auto mt-10 w-16 h-px bg-rust-500" />
            <p className="mt-10 text-[#484848] text-lg font-light max-w-2xl mx-auto leading-relaxed">
              Assertions without evidence are exposure. FrostGate enforces a closed loop
              between claim and proof — every finding anchored, every control mapped,
              every report signed.
            </p>
          </div>
        </section>

        {/* ── FINAL CTA ─────────────────────────────────────────────── */}
        <section className="py-40 px-8">
          <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-12">
            <div>
              <p className="text-[10px] tracking-[0.22em] uppercase text-[#333] mb-4">Operator Access</p>
              <h2 className="font-display text-6xl font-bold uppercase text-white tracking-tight leading-none">
                Ready to<br />Deploy?
              </h2>
            </div>
            <div className="flex flex-col sm:flex-row gap-4 shrink-0">
              <a
                href="https://console.frostgate.ai"
                className="px-10 py-4 bg-white text-black text-sm tracking-[0.12em] uppercase font-semibold hover:bg-[#d4d4d4] transition-colors text-center"
              >
                Open Console
              </a>
              <a
                href="https://app.frostgate.ai"
                className="px-10 py-4 border border-[#222] text-[#555] text-sm tracking-[0.12em] uppercase font-medium hover:border-[#3a3a3a] hover:text-[#888] transition-colors text-center"
              >
                Client Portal
              </a>
            </div>
          </div>
        </section>
      </main>

      {/* ── FOOTER ────────────────────────────────────────────────── */}
      <footer className="border-t border-[#1c1c1c] py-10 px-8">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <span className="text-[10px] tracking-[0.18em] uppercase text-[#2e2e2e]">
              © {new Date().getFullYear()} FrostGate
            </span>
          </div>
          <div className="flex gap-8">
            {[
              ['Console', 'https://console.frostgate.ai'],
              ['Client Portal', 'https://app.frostgate.ai'],
            ].map(([label, href]) => (
              <a
                key={label}
                href={href}
                className="text-[10px] tracking-[0.16em] uppercase text-[#2e2e2e] hover:text-[#555] transition-colors"
              >
                {label}
              </a>
            ))}
          </div>
        </div>
      </footer>
    </>
  );
}
