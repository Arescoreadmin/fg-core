'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

// MCIM reference: MCIM-18.6-CMD-CENTER
// sourceOfTruth: /api/core/control-tower/snapshot
// drillDown: see props

export interface WidgetShellProps {
  mcimId: string;
  authority: string;
  capability: string;
  sourceOfTruth: string;
  drillDown: string;
  refreshPolicy: string;
  lastUpdated?: string;
  confidence?: number;
  title: string;
  className?: string;
  children: React.ReactNode;
  investigationSupport?: boolean;
  exportReady?: boolean;
  correlationId?: string;
}

export default function WidgetShell({
  mcimId,
  authority,
  capability,
  sourceOfTruth,
  drillDown,
  refreshPolicy,
  lastUpdated,
  confidence,
  title,
  className,
  children,
  investigationSupport,
  exportReady,
  correlationId,
}: WidgetShellProps) {
  const [metaOpen, setMetaOpen] = useState(false);

  const confidencePct =
    confidence !== undefined ? `${Math.round(confidence * 100)}%` : null;

  return (
    <Card className={className} aria-label={`widget-${mcimId}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold text-foreground">{title}</CardTitle>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs text-muted"
            aria-expanded={metaOpen}
            aria-controls={`meta-${mcimId}`}
            onClick={() => setMetaOpen((v) => !v)}
          >
            Source
            {metaOpen ? (
              <ChevronUp className="ml-1 h-3 w-3" aria-hidden="true" />
            ) : (
              <ChevronDown className="ml-1 h-3 w-3" aria-hidden="true" />
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {children}
        {metaOpen && (
          <div
            id={`meta-${mcimId}`}
            className="mt-4 rounded-md border border-border bg-muted/30 p-3 text-[10px] text-muted space-y-1"
            aria-label="widget-metadata"
          >
            <div className="flex justify-between">
              <span className="font-semibold uppercase tracking-wide">MCIM</span>
              <span className="font-mono">{mcimId}</span>
            </div>
            <div className="flex justify-between">
              <span className="font-semibold uppercase tracking-wide">Authority</span>
              <span>{authority}</span>
            </div>
            <div className="flex justify-between">
              <span className="font-semibold uppercase tracking-wide">Capability</span>
              <span>{capability}</span>
            </div>
            <div className="flex justify-between">
              <span className="font-semibold uppercase tracking-wide">Source</span>
              <span className="font-mono truncate max-w-[160px]">{sourceOfTruth}</span>
            </div>
            <div className="flex justify-between">
              <span className="font-semibold uppercase tracking-wide">Refresh</span>
              <span>{refreshPolicy}</span>
            </div>
            {confidencePct && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Confidence</span>
                <span>{confidencePct}</span>
              </div>
            )}
            {lastUpdated && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Updated</span>
                <span>{new Date(lastUpdated).toLocaleString()}</span>
              </div>
            )}
            {investigationSupport !== undefined && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Investigation</span>
                <span>{investigationSupport ? 'Supported' : 'Not supported'}</span>
              </div>
            )}
            {exportReady !== undefined && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Export</span>
                <span>{exportReady ? 'Ready' : 'Not available'}</span>
              </div>
            )}
            {correlationId && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Correlation</span>
                <span className="font-mono truncate max-w-[160px]">{correlationId}</span>
              </div>
            )}
            <div className="pt-1">
              <Link
                href={drillDown}
                className="inline-flex items-center gap-1 text-primary hover:underline"
              >
                Drill down <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </Link>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
