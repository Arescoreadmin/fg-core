'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  Brain,
  Building2,
  ClipboardCheck,
  ClipboardList,
  Command,
  Database,
  FlaskConical,
  GitBranch,
  Layers,
  LayoutDashboard,
  LogOut,
  MessageSquare,
  Microscope,
  Package,
  Radio,
  Settings,
  ShieldCheck,
  Users,
  X,
} from 'lucide-react';
import { useSession } from 'next-auth/react';
import { CONSOLE_REGISTRY } from '@fg/navigation';
import type { NavigationGroup } from '@fg/navigation';
import { cn } from '@/lib/cn';
import { FrostGateShield } from '@/components/governance/FrostGateShield';
import { ThemeToggle } from '@/components/ui/ThemeToggle';
import { getNavigationItemsForPrincipal } from '@/lib/consoleAccess';

const ICON_MAP: Record<string, LucideIcon> = {
  'executive-intelligence': Brain,
  'command-center': LayoutDashboard,
  'operations-center': Command,
  'control-tower': Radio,
  'readiness': Activity,
  'field-assessments': ClipboardCheck,
  'policies': ShieldCheck,
  'providers': Package,
  'ai-workspace': MessageSquare,
  'corpus': Database,
  'retrieval': Layers,
  'workforce-intel': Users,
  'provenance': GitBranch,
  'decisions': ShieldCheck,
  'audit-forensics': Microscope,
  'evaluation-lab': FlaskConical,
  'keys': Settings,
  'clients': Building2,
  'settings': Settings,
  'assessments': ClipboardList,
};

const GROUP_ORDER: NavigationGroup[] = [
  'Operations',
  'Governance',
  'Intelligence',
  'Trust',
  'Compliance',
  'Administration',
];

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export function Sidebar({ isOpen = false, onClose }: SidebarProps) {
  const pathname = usePathname();
  const { data: session } = useSession();

  const visibleItems = getNavigationItemsForPrincipal(CONSOLE_REGISTRY.getAllItems(), session);

  const navGroups = GROUP_ORDER.map((groupId) => {
    const items = visibleItems.filter((item) => item.group === groupId);
    return { id: groupId, items };
  }).filter((g) => g.items.length > 0);

  function isActive(route: string) {
    if (route === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(route);
  }

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-50 flex h-screen w-56 shrink-0 flex-col border-r border-border bg-surface md:relative md:flex',
        isOpen ? 'flex' : 'hidden md:flex',
      )}
    >
      <div className="flex h-14 items-center gap-2.5 border-b border-border px-4">
        <FrostGateShield size={26} />
        <span className="text-sm font-semibold tracking-wide text-foreground">FrostGate</span>
        <span className="ml-auto rounded-full bg-primary/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-primary">
          Console
        </span>
        {onClose && (
          <button
            type="button"
            aria-label="Close navigation"
            className="ml-1 rounded p-1 text-muted hover:bg-surface-2 hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary md:hidden"
            onClick={onClose}
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        )}
      </div>

      <nav
        id="sidebar-nav"
        aria-label="Main navigation"
        className="flex-1 overflow-y-auto px-2 py-3"
      >
        {navGroups.map(({ id: groupId, items }, gi) => (
          <div key={groupId} className={cn(gi > 0 && 'mt-4')}>
            <p className="mb-1 px-3 text-[9px] font-semibold uppercase tracking-widest text-muted/40">
              {groupId}
            </p>
            {items.map((item) => {
              const active = isActive(item.route);
              const Icon = ICON_MAP[item.id];
              return (
                <Link
                  key={item.route}
                  href={item.route}
                  aria-current={active ? 'page' : undefined}
                  onClick={onClose}
                  className={cn(
                    'flex items-center gap-2.5 rounded px-3 py-2 text-sm transition-colors',
                    active
                      ? 'bg-primary/10 font-medium text-primary'
                      : 'text-muted hover:bg-surface-2 hover:text-foreground',
                  )}
                >
                  {Icon && <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />}
                  {item.title}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="border-t border-border px-4 py-3">
        <ThemeToggle />
        <a
          href="/api/auth/logout"
          className="mb-2 flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-muted transition-colors hover:bg-surface-2 hover:text-foreground"
        >
          <LogOut className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          Sign out
        </a>
        <p className="text-[10px] text-muted">FrostGate v0.2.0</p>
        <p className="mt-0.5 text-[10px] text-muted/50">AI Governance Platform</p>
      </div>
    </aside>
  );
}
