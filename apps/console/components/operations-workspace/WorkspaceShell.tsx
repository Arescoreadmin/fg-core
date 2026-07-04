'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const MCIM_ID = 'MCIM-18.6-OPS-WORKSPACE';
const AUTHORITY = 'Operations Workspace Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

export interface WorkspaceShellProps {
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
  workflowStage?: string;
  delegationSupported?: boolean;
  playbook?: string;
  tenantId?: string;
}

export default function WorkspaceShell({
  mcimId,
  authority,
  capability,
  sourceOfTruth: sot,
  drillDown: dd,
  refreshPolicy,
  lastUpdated,
  confidence,
  title,
  className,
  children,
  workflowStage,
  delegationSupported,
  playbook,
  tenantId,
}: WorkspaceShellProps) {
  const [metaOpen, setMetaOpen] = useState(false);

  const confidencePct =
    confidence !== undefined ? `${Math.round(confidence * 100)}%` : null;

  return (
    <Card className={className} aria-label={`workspace-panel-${mcimId}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold text-foreground">{title}</CardTitle>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs text-muted"
            aria-expanded={metaOpen}
            aria-controls={`ws-meta-${mcimId}`}
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
            id={`ws-meta-${mcimId}`}
            className="mt-4 rounded-md border border-border bg-muted/30 p-3 text-[10px] text-muted space-y-1"
            aria-label="workspace-panel-metadata"
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
              <span className="font-mono truncate max-w-[160px]">{sot}</span>
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
            {workflowStage && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Workflow Stage</span>
                <span>{workflowStage}</span>
              </div>
            )}
            {delegationSupported !== undefined && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Delegation</span>
                <span>{delegationSupported ? 'Supported' : 'Not supported'}</span>
              </div>
            )}
            {playbook && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Playbook</span>
                <span className="truncate max-w-[160px]">{playbook}</span>
              </div>
            )}
            {tenantId && (
              <div className="flex justify-between">
                <span className="font-semibold uppercase tracking-wide">Tenant</span>
                <span className="font-mono truncate max-w-[160px]">{tenantId}</span>
              </div>
            )}
            <div className="pt-1">
              <Link
                href={dd}
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

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
