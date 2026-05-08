'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldCheck,
  ClipboardList,
  FileText,
  Key,
  Package,
  Search,
  TrendingUp,
  Radio,
  MessageSquare,
} from 'lucide-react';
import { cn } from '@/lib/cn';
import { FrostGateShield } from '@/components/governance/FrostGateShield';

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Operational',
    items: [
      { label: 'Overview',      href: '/dashboard',               icon: LayoutDashboard },
      { label: 'Control Tower', href: '/dashboard/control-tower', icon: Radio },
      { label: 'API Keys',      href: '/keys',                    icon: Key },
    ],
  },
  {
    label: 'Decision Layer',
    items: [
      { label: 'Decisions',  href: '/dashboard/decisions', icon: ShieldCheck },
      { label: 'Forensics',  href: '/dashboard/forensics', icon: Search },
      { label: 'Alignment',  href: '/dashboard/alignment', icon: TrendingUp },
      { label: 'AI Assistant', href: '/dashboard/assistant', icon: MessageSquare },
    ],
  },
  {
    label: 'Compliance',
    items: [
      { label: 'Audit Log', href: '/audit',   icon: ClipboardList },
      { label: 'Reports',   href: '/reports', icon: FileText },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'Assessments', href: '/assessment', icon: ClipboardList },
      { label: 'Products',    href: '/products',   icon: Package },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();

  function isActive(href: string) {
    if (href === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(href);
  }

  return (
    <aside className="flex h-screen w-56 shrink-0 flex-col border-r border-border bg-surface">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 px-4 border-b border-border">
        <FrostGateShield size={26} />
        <span className="text-sm font-semibold tracking-wide text-foreground">FrostGate</span>
        <span className="ml-auto rounded-full bg-primary/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-primary">
          Console
        </span>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
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
                  className={cn(
                    'flex items-center gap-2.5 rounded px-3 py-2 text-sm transition-colors',
                    active
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-muted hover:bg-surface-2 hover:text-foreground',
                  )}
                >
                  <item.icon className="h-3.5 w-3.5 shrink-0" />
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-4 py-3">
        <p className="text-[10px] text-muted">FrostGate v0.2.0</p>
        <p className="text-[10px] text-muted/50 mt-0.5">AI Governance Platform</p>
      </div>
    </aside>
  );
}
