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
  Activity,
  ChevronRight,
  Zap,
} from 'lucide-react';
import { cn } from '@/lib/cn';

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  children?: { label: string; href: string }[];
}

const NAV: NavItem[] = [
  {
    label: 'Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
    children: [
      { label: 'Overview', href: '/dashboard' },
      { label: 'Alignment', href: '/dashboard/alignment' },
      { label: 'Control Tower', href: '/dashboard/control-tower' },
      { label: 'Decisions', href: '/dashboard/decisions' },
      { label: 'Forensics', href: '/dashboard/forensics' },
    ],
  },
  { label: 'Assessments', href: '/assessment', icon: ClipboardList },
  { label: 'Reports', href: '/reports', icon: FileText },
  { label: 'Audit Log', href: '/audit', icon: ShieldCheck },
  { label: 'API Keys', href: '/keys', icon: Key },
  { label: 'Products', href: '/products', icon: Package },
  { label: 'Health', href: '/dashboard', icon: Activity },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-border bg-surface">
      {/* Logo */}
      <div className="flex h-16 items-center gap-2 px-5 border-b border-border">
        <div className="flex h-7 w-7 items-center justify-center rounded bg-primary">
          <Zap className="h-4 w-4 text-white" />
        </div>
        <span className="text-sm font-semibold tracking-wide text-foreground">FrostGate</span>
        <span className="ml-auto rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
          CONSOLE
        </span>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-4 px-3">
        {NAV.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.children?.some((c) => pathname === c.href) ?? false);
          const isParentActive = item.children
            ? item.children.some((c) => pathname.startsWith(c.href))
            : pathname === item.href;

          return (
            <div key={item.href} className="mb-1">
              <Link
                href={item.href}
                className={cn(
                  'flex items-center gap-2.5 rounded px-3 py-2 text-sm transition-colors',
                  isParentActive
                    ? 'bg-primary/10 text-primary font-medium'
                    : 'text-muted hover:bg-surface-2 hover:text-foreground'
                )}
              >
                <item.icon className="h-4 w-4 shrink-0" />
                <span className="flex-1">{item.label}</span>
                {item.children && (
                  <ChevronRight
                    className={cn(
                      'h-3.5 w-3.5 transition-transform',
                      isParentActive && 'rotate-90'
                    )}
                  />
                )}
              </Link>

              {item.children && isParentActive && (
                <div className="ml-9 mt-1 space-y-0.5">
                  {item.children.map((child) => (
                    <Link
                      key={child.href}
                      href={child.href}
                      className={cn(
                        'block rounded px-2 py-1.5 text-xs transition-colors',
                        pathname === child.href
                          ? 'text-primary font-medium'
                          : 'text-muted hover:text-foreground'
                      )}
                    >
                      {child.label}
                    </Link>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-5 py-4">
        <p className="text-xs text-muted">FrostGate v0.2.0</p>
        <p className="text-xs text-muted/60 mt-0.5">AI Governance Platform</p>
      </div>
    </aside>
  );
}
