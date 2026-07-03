import type { Metadata } from 'next';
import Link from 'next/link';
import { LogoutButton } from '@/components/LogoutButton';
import { ThemeToggle } from '@/components/ThemeToggle';
import { PORTAL_REGISTRY } from '@fg/navigation';
import './globals.css';

export const metadata: Metadata = {
  title: 'FrostGate — Client Portal',
  description: 'AI governance assessment results and remediation tracking.',
};

const NAV_LINKS = PORTAL_REGISTRY.getAllItems()
  .filter((item) => item.visibility === 'visible' && item.tier !== 'hidden')
  .sort((a, b) => {
    const tierOrder: Record<string, number> = { primary: 0, secondary: 1, contextual: 2 };
    return (tierOrder[a.tier] ?? 9) - (tierOrder[b.tier] ?? 9);
  })
  .map((item) => ({ href: item.route, label: item.title }));

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: `(function(){var t=localStorage.getItem('fg-theme');if(t==='light'){document.documentElement.classList.remove('dark')}else{document.documentElement.classList.add('dark')}})()` }} />
      </head>
      <body className="min-h-screen bg-background text-foreground">
        <header className="border-b border-border bg-surface sticky top-0 z-10">
          <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
            <Link href="/" className="text-sm font-semibold text-foreground hover:text-primary transition-colors">
              FrostGate <span className="text-muted font-normal">Client Portal</span>
            </Link>
            <nav aria-label="Main navigation">
              <ul className="flex items-center gap-1 flex-wrap">
                {NAV_LINKS.map((link) => (
                  <li key={link.href}>
                    <Link
                      href={link.href}
                      className="px-2.5 py-1 rounded text-xs text-muted hover:text-foreground hover:bg-surface-2 transition-colors"
                    >
                      {link.label}
                    </Link>
                  </li>
                ))}
                <li>
                  <ThemeToggle />
                </li>
                <li>
                  <LogoutButton />
                </li>
              </ul>
            </nav>
          </div>
        </header>

        <main className="max-w-5xl mx-auto px-4 py-6">
          {children}
        </main>

        <footer className="border-t border-border mt-12 py-4">
          <div className="max-w-5xl mx-auto px-4 flex items-center justify-between text-xs text-muted">
            <span>FrostGate AI Governance Platform</span>
            <span>Client Portal — read-only view</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
