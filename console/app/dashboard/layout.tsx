'use client';

import { useState } from 'react';
import { Menu } from 'lucide-react';
import { Sidebar } from '@/components/layout/Sidebar';
import { FrostGateShield } from '@/components/governance/FrostGateShield';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-[100] focus:rounded focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:outline focus:outline-2 focus:outline-primary"
      >
        Skip to content
      </a>

      <div className="flex h-screen overflow-hidden bg-background">
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-40 bg-black/50 md:hidden"
            aria-hidden="true"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <div className="flex h-12 shrink-0 items-center gap-3 border-b border-border bg-surface px-4 md:hidden">
            <button
              type="button"
              aria-label="Open navigation"
              aria-expanded={sidebarOpen}
              aria-controls="sidebar-nav"
              className="rounded p-1 text-muted hover:bg-surface-2 hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="h-5 w-5" aria-hidden="true" />
            </button>
            <FrostGateShield size={20} />
            <span className="text-sm font-semibold text-foreground">FrostGate</span>
          </div>

          <main
            id="main-content"
            tabIndex={-1}
            className="flex-1 overflow-y-auto focus-visible:outline-none"
          >
            {children}
          </main>
        </div>
      </div>
    </>
  );
}
