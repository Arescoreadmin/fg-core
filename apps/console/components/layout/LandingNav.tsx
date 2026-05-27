'use client';

import { useRef, useState } from 'react';
import Link from 'next/link';
import { Menu, X, ChevronDown } from 'lucide-react';
import { FrostGateShield } from '@/components/governance/FrostGateShield';
import { Button } from '@/components/ui/button';

const PRODUCTS = [
  {
    name: 'Snapshot',
    price: '$299 one-time',
    desc: 'AI risk assessment + advisory report',
    href: '/onboarding',
  },
  {
    name: 'Intelligence',
    price: '$5,000 / year',
    desc: 'Monitoring, benchmarking, RAG recommendations',
    href: '/onboarding?tier=intelligence',
  },
  {
    name: 'Control',
    price: '$50,000 / year',
    desc: 'Runtime AI gateway, OPA enforcement, audit log',
    href: 'mailto:sales@frostgate.ai',
    sales: true,
  },
  {
    name: 'Autonomous',
    price: '$100,000+ / year',
    desc: 'Continuous monitoring, drift detection, auto-remediation',
    href: 'mailto:sales@frostgate.ai',
    sales: true,
  },
];

const NAV_LINKS = [
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Security', href: '#security' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'FAQ', href: '#faq' },
];

export function LandingNav() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [productsOpen, setProductsOpen] = useState(false);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const openProducts = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    setProductsOpen(true);
  };
  const scheduleClose = () => {
    closeTimer.current = setTimeout(() => setProductsOpen(false), 120);
  };

  return (
    <nav className="sticky top-0 z-50 border-b border-border bg-background/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">

        {/* Wordmark */}
        <Link href="/" className="flex items-center gap-2.5 shrink-0">
          <FrostGateShield size={28} />
          <div className="flex flex-col leading-none">
            <span className="font-semibold text-foreground text-sm tracking-wide">FrostGate</span>
            <span className="text-[10px] text-muted tracking-widest uppercase">
              Trust But Verify
            </span>
          </div>
        </Link>

        {/* Desktop links */}
        <div className="hidden items-center gap-1 text-sm text-muted md:flex">
          {/* Products dropdown */}
          <div
            className="relative"
            onMouseEnter={openProducts}
            onMouseLeave={scheduleClose}
          >
            <button
              className="flex items-center gap-1 px-3 py-2 rounded-md hover:text-foreground hover:bg-surface-2 transition-colors"
              aria-expanded={productsOpen}
              aria-haspopup="true"
            >
              Products
              <ChevronDown
                className={`h-3.5 w-3.5 transition-transform duration-150 ${productsOpen ? 'rotate-180' : ''}`}
              />
            </button>

            {productsOpen && (
              <div
                className="absolute left-0 top-full pt-2 w-72 animate-fade-in z-50"
                onMouseEnter={openProducts}
                onMouseLeave={scheduleClose}
              >
                <div className="rounded-xl border border-border bg-surface-2 shadow-xl overflow-hidden">
                  {PRODUCTS.map((p) => (
                    <Link
                      key={p.name}
                      href={p.href}
                      className="flex items-start gap-3 px-4 py-3 hover:bg-surface-3 transition-colors border-b border-border last:border-0"
                      onClick={() => setProductsOpen(false)}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-foreground">{p.name}</span>
                          {p.sales && (
                            <span className="text-[10px] text-muted border border-border rounded px-1.5 py-0.5">
                              Contact sales
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-muted mt-0.5 truncate">{p.desc}</p>
                      </div>
                      <span className="text-xs text-primary font-medium shrink-0 mt-0.5">
                        {p.price}
                      </span>
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </div>

          {NAV_LINKS.map((l) => (
            <a
              key={l.label}
              href={l.href}
              className="px-3 py-2 rounded-md hover:text-foreground hover:bg-surface-2 transition-colors"
            >
              {l.label}
            </a>
          ))}
        </div>

        {/* Desktop CTAs */}
        <div className="hidden md:flex items-center gap-3 shrink-0">
          <Link href="/dashboard">
            <Button variant="outline" size="sm">Sign In</Button>
          </Link>
          <Link href="/onboarding">
            <Button size="sm">Get Started</Button>
          </Link>
        </div>

        {/* Mobile hamburger */}
        <button
          className="md:hidden flex items-center justify-center h-9 w-9 rounded border border-border text-muted hover:text-foreground transition-colors"
          onClick={() => setMobileOpen((v) => !v)}
          aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={mobileOpen}
          aria-controls="mobile-menu"
        >
          {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
        </button>
      </div>

      {/* Mobile dropdown */}
      {mobileOpen && (
        <div
          id="mobile-menu"
          className="md:hidden border-t border-border bg-background/95 backdrop-blur-md px-4 py-3 animate-fade-in"
        >
          <p className="text-[10px] uppercase tracking-widest text-muted px-2 pb-1">Products</p>
          {PRODUCTS.map((p) => (
            <Link
              key={p.name}
              href={p.href}
              className="flex items-center justify-between px-2 py-2 rounded-md hover:bg-surface-2 transition-colors"
              onClick={() => setMobileOpen(false)}
            >
              <span className="text-sm text-foreground">{p.name}</span>
              <span className="text-xs text-primary">{p.price}</span>
            </Link>
          ))}

          <div className="border-t border-border mt-2 pt-2">
            {NAV_LINKS.map((l) => (
              <a
                key={l.label}
                href={l.href}
                className="block px-2 py-2 text-sm text-muted hover:text-foreground rounded-md hover:bg-surface-2 transition-colors"
                onClick={() => setMobileOpen(false)}
              >
                {l.label}
              </a>
            ))}
          </div>

          <div className="border-t border-border mt-2 pt-3 flex flex-col gap-2">
            <Link href="/dashboard" onClick={() => setMobileOpen(false)}>
              <Button variant="outline" size="sm" className="w-full">Sign In</Button>
            </Link>
            <Link href="/onboarding" onClick={() => setMobileOpen(false)}>
              <Button size="sm" className="w-full">Get Started</Button>
            </Link>
          </div>
        </div>
      )}
    </nav>
  );
}
