'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldCheck,
  ClipboardList,
  ClipboardCheck,
  Database,
  GitBranch,
  FlaskConical,
  Activity,
  Package,
  Layers,
  Microscope,
  Radio,
  MessageSquare,
  Settings,
  Users,
  Building2,
  LogOut,
  X,
} from 'lucide-react';
import { cn } from '@/lib/cn';
import { FrostGateShield } from '@/components/governance/FrostGateShield';
import { ThemeToggle } from '@/components/ui/ThemeToggle';

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Operations',
    items: [
      { label: 'Command Center',  href: '/dashboard',               icon: LayoutDashboard },
      { label: 'Control Tower',   href: '/dashboard/control-tower', icon: Radio },
    ],
  },
  {
    label: 'AI & Knowledge',
    items: [
      { label: 'AI Workspace',    href: '/dashboard/assistant',     icon: MessageSquare },
      { label: 'Corpus',          href: '/dashboard/corpus',        icon: Database },
      { label: 'Retrieval',       href: '/dashboard/retrieval',     icon: Layers },
      { label: 'Provenance',      href: '/dashboard/provenance',    icon: GitBranch },
    ],
  },
  {
    label: 'Governance',
    items: [
      { label: 'Policies',           href: '/dashboard/policies',    icon: ShieldCheck },
      { label: 'Providers',          href: '/dashboard/providers',   icon: Package },
      { label: 'Readiness',          href: '/dashboard/readiness',   icon: Activity },
      { label: 'Field Assessments',  href: '/field-assessment',      icon: ClipboardCheck },
    ],
  },
  {
    label: 'Compliance',
    items: [
      { label: 'Audit & Forensics', href: '/dashboard/forensics',  icon: Microscope },
      { label: 'Decisions',       href: '/dashboard/decisions',     icon: ShieldCheck },
      { label: 'Evaluation Lab',  href: '/dashboard/evaluation',    icon: FlaskConical },
    ],
  },
  {
    label: 'Workforce',
    items: [
      { label: 'Workforce Intel', href: '/dashboard/workforce',     icon: Users },
    ],
  },
  {
    label: 'Admin',
    items: [
      { label: 'Clients',         href: '/admin/tenants',           icon: Building2 },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'Settings',        href: '/dashboard/settings',      icon: Settings },
      { label: 'Assessments',     href: '/assessment',              icon: ClipboardList },
    ],
  },
];

export function Sidebar({ isOpen = false, onClose }: SidebarProps) {
  const pathname = usePathname();

  function isActive(href: string) {
    if (href === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(href);
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
        {NAV_GROUPS.map((group, gi) => (
          <div key={group.label} className={cn(gi > 0 && 'mt-4')}>
            <p className="mb-1 px-3 text-[9px] font-semibold uppercase tracking-widest text-muted/40">
              {group.label}
            </p>
            {group.items.map((item) => {
              const active = isActive(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={active ? 'page' : undefined}
                  onClick={onClose}
                  className={cn(
                    'flex items-center gap-2.5 rounded px-3 py-2 text-sm transition-colors',
                    active
                      ? 'bg-primary/10 font-medium text-primary'
                      : 'text-muted hover:bg-surface-2 hover:text-foreground',
                  )}
                >
                  <item.icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="border-t border-border px-4 py-3">
        <ThemeToggle />
        <Link
          href="/api/auth/logout"
          className="mb-2 flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-muted hover:bg-surface-2 hover:text-foreground transition-colors"
        >
          <LogOut className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          Sign out
        </Link>
        <p className="text-[10px] text-muted">FrostGate v0.2.0</p>
        <p className="mt-0.5 text-[10px] text-muted/50">AI Governance Platform</p>
      </div>
    </aside>
  );
}
