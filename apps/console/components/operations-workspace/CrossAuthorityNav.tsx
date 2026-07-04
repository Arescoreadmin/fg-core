'use client';

import { useCallback } from 'react';
import Link from 'next/link';
import {
  ClipboardList,
  FileSearch,
  CheckSquare,
  AlertTriangle,
  FileText,
  ShieldCheck,
  Gavel,
  Activity,
  RotateCcw,
  Globe,
  Users,
} from 'lucide-react';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-CROSS-AUTHORITY-NAV';
const AUTHORITY = 'Navigation Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

interface AuthorityStep {
  name: string;
  path: string;
  icon: React.ElementType;
}

const AUTHORITY_CHAIN: AuthorityStep[] = [
  { name: 'Assessment', path: '/assessment', icon: ClipboardList },
  { name: 'Evidence', path: '/dashboard/provenance', icon: FileSearch },
  { name: 'Verification', path: '/dashboard/readiness', icon: CheckSquare },
  { name: 'Findings', path: '/dashboard/forensics', icon: AlertTriangle },
  { name: 'Report', path: '/reports', icon: FileText },
  { name: 'Governance', path: '/governance/topology', icon: ShieldCheck },
  { name: 'Decision', path: '/dashboard/decisions', icon: Gavel },
  { name: 'Simulation', path: '/dashboard/evaluation', icon: Activity },
  { name: 'Replay', path: '/dashboard/forensics', icon: RotateCcw },
  { name: 'Portal', path: '/dashboard/alignment', icon: Globe },
  { name: 'Customer', path: '/products', icon: Users },
];

interface CrossAuthorityNavProps {
  currentAuthority: string;
  onNavigate?: (authority: string, path: string) => void;
}

export default function CrossAuthorityNav({
  currentAuthority,
  onNavigate,
}: CrossAuthorityNavProps) {
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLAnchorElement>, step: AuthorityStep) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        onNavigate?.(step.name, step.path);
      }
    },
    [onNavigate],
  );

  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Cross-Authority Navigation"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="static"
      title="Cross-Authority Navigation"
    >
      <nav aria-label="cross-authority-nav">
        <ol className="flex flex-wrap gap-1 items-center" role="list">
          {AUTHORITY_CHAIN.map((step, idx) => {
            const Icon = step.icon;
            const isCurrent = step.name === currentAuthority;

            return (
              <li key={step.name} className="flex items-center gap-1">
                {idx > 0 && (
                  <span className="text-muted/40 text-xs" aria-hidden="true">›</span>
                )}
                <Link
                  href={step.path}
                  aria-current={isCurrent ? 'page' : undefined}
                  onClick={() => onNavigate?.(step.name, step.path)}
                  onKeyDown={(e) => handleKeyDown(e, step)}
                  className={[
                    'inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary',
                    isCurrent
                      ? 'bg-primary text-white'
                      : 'bg-surface-2 text-foreground hover:bg-surface-3',
                  ].join(' ')}
                >
                  <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
                  {step.name}
                </Link>
              </li>
            );
          })}
        </ol>
      </nav>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
