'use client';

import { useRef, useEffect } from 'react';
import { X } from 'lucide-react';
import { Button } from '@/components/ui/button';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Control Tower Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

export interface InvestigationItem {
  label: string;
  value: string;
  href?: string;
}

interface InvestigationDrawerProps {
  widgetName: string;
  mcimId: string;
  authority: string;
  capability: string;
  sourceOfTruth: string;
  refreshPolicy: string;
  confidence?: number;
  lastUpdated?: string;
  drillDown: string;
  investigationItems?: InvestigationItem[];
  open: boolean;
  onClose: () => void;
}

export default function InvestigationDrawer({
  widgetName,
  mcimId,
  authority,
  capability,
  sourceOfTruth: sourceProp,
  refreshPolicy,
  confidence,
  lastUpdated,
  drillDown: drillDownProp,
  investigationItems = [],
  open,
  onClose,
}: InvestigationDrawerProps) {
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (open && closeButtonRef.current) {
      closeButtonRef.current.focus();
    }
  }, [open]);

  if (!open) return null;

  const confidencePct =
    confidence !== undefined ? `${Math.round(confidence * 100)}%` : null;

  return (
    <div
      role="complementary"
      aria-label="investigation-drawer"
      data-testid="investigation-drawer"
      className="fixed inset-y-0 right-0 z-50 w-80 border-l border-border bg-background shadow-xl flex flex-col"
      tabIndex={0}
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-foreground">Investigation</h2>
          <p className="text-[10px] text-muted">{widgetName}</p>
        </div>
        <Button
          ref={closeButtonRef}
          variant="ghost"
          size="sm"
          className="h-7 w-7 p-0"
          aria-label="close-investigation"
          onClick={onClose}
          tabIndex={0}
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </div>

      {/* Metadata table */}
      <div className="border-b border-border px-4 py-3">
        <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted">
          Widget Metadata
        </h3>
        <table className="w-full text-[10px]">
          <tbody className="space-y-1">
            <tr>
              <td className="pr-3 font-semibold text-muted/70 uppercase tracking-wide">MCIM</td>
              <td className="font-mono text-foreground">{mcimId}</td>
            </tr>
            <tr>
              <td className="pr-3 font-semibold text-muted/70 uppercase tracking-wide">Authority</td>
              <td className="text-foreground">{authority}</td>
            </tr>
            <tr>
              <td className="pr-3 font-semibold text-muted/70 uppercase tracking-wide">Capability</td>
              <td className="text-foreground">{capability}</td>
            </tr>
            <tr>
              <td className="pr-3 font-semibold text-muted/70 uppercase tracking-wide">Source</td>
              <td className="font-mono text-foreground truncate max-w-[160px]">{sourceProp}</td>
            </tr>
            <tr>
              <td className="pr-3 font-semibold text-muted/70 uppercase tracking-wide">Refresh</td>
              <td className="text-foreground">{refreshPolicy}</td>
            </tr>
            {confidencePct && (
              <tr>
                <td className="pr-3 font-semibold text-muted/70 uppercase tracking-wide">Confidence</td>
                <td className="text-foreground">{confidencePct}</td>
              </tr>
            )}
            {lastUpdated && (
              <tr>
                <td className="pr-3 font-semibold text-muted/70 uppercase tracking-wide">Updated</td>
                <td className="text-foreground">{new Date(lastUpdated).toLocaleString()}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Investigation items */}
      <div className="flex-1 overflow-y-auto px-4 py-3">
        <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted">
          Related Records
        </h3>
        {investigationItems.length === 0 ? (
          <div
            aria-label="investigation-empty"
            data-testid="investigation-empty"
            className="py-4 text-center text-sm text-muted"
          >
            No related records available
          </div>
        ) : (
          <ul className="space-y-2">
            {investigationItems.map((item, idx) => (
              <li key={idx} className="flex items-start justify-between gap-2 text-[11px]">
                <span className="font-medium text-muted/70">{item.label}</span>
                {item.href ? (
                  <a
                    href={item.href}
                    className="text-primary hover:underline font-mono truncate max-w-[140px]"
                    tabIndex={0}
                  >
                    {item.value}
                  </a>
                ) : (
                  <span className="text-foreground font-mono truncate max-w-[140px]">{item.value}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Footer */}
      <div className="border-t border-border px-4 py-2">
        <p className="text-[9px] text-muted/50">
          {MCIM_ID} · {AUTHORITY} · <span className="font-mono">{sourceOfTruth}</span>
        </p>
      </div>
    </div>
  );
}
