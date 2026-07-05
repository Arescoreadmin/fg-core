'use client';
import Link from 'next/link';
import { ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { useState } from 'react';

const MCIM_ID = 'MCIM-18.6-PORTAL-SHELL';
const AUTHORITY = 'Customer Portal Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/';
const customerSafe = true;

export interface PortalShellProps {
  mcimId: string;
  authority: string;
  capability: string;
  sourceOfTruth: string;
  drillDown: string;
  title: string;
  lastUpdated?: string;
  children: React.ReactNode;
  className?: string;
}

export default function PortalShell({
  mcimId,
  authority,
  capability,
  sourceOfTruth: sot,
  drillDown: dd,
  title,
  lastUpdated,
  children,
  className = '',
}: PortalShellProps) {
  const [open, setOpen] = useState(false);

  return (
    <div className={`rounded-lg border border-border bg-surface ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        <button
          type="button"
          aria-expanded={open}
          aria-label="Toggle source metadata"
          className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-muted hover:text-foreground hover:bg-surface-2 transition-colors"
          onClick={() => setOpen((v) => !v)}
        >
          Source
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
      </div>

      {/* Collapsible metadata panel */}
      {open && (
        <div className="px-4 py-3 border-b border-border bg-surface-2 text-xs space-y-1.5">
          <div className="flex flex-wrap gap-x-6 gap-y-1">
            <span className="text-muted">
              <span className="font-medium text-foreground">MCIM ID:</span>{' '}
              <span className="font-mono">{mcimId}</span>
            </span>
            <span className="text-muted">
              <span className="font-medium text-foreground">Authority:</span> {authority}
            </span>
            <span className="text-muted">
              <span className="font-medium text-foreground">Capability:</span> {capability}
            </span>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-1">
            <span className="text-muted">
              <span className="font-medium text-foreground">Source:</span>{' '}
              <span className="font-mono">{sot}</span>
            </span>
            <span className="text-muted">
              <span className="font-medium text-foreground">Drill-down:</span>{' '}
              <Link
                href={dd}
                className="inline-flex items-center gap-0.5 underline hover:text-foreground transition-colors"
              >
                {dd} <ExternalLink size={10} />
              </Link>
            </span>
          </div>
        </div>
      )}

      {/* Content */}
      <div className="px-4 py-4">{children}</div>

      {/* Footer */}
      {lastUpdated && (
        <div className="px-4 py-2 border-t border-border">
          <p className="text-[11px] text-muted">
            Last updated: {new Date(lastUpdated).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
