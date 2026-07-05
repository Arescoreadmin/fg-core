'use client';

import { useSearchParams } from 'next/navigation';
import {
  WORKSPACE_CONTEXT_KEYS,
  buildWorkspaceUrl as libBuildWorkspaceUrl,
  type WorkspaceContext,
} from '@/lib/workspaceContext';

export type { WorkspaceContext } from '@/lib/workspaceContext';
export type { WorkspaceLink } from './CrossWorkspaceNav';

// Context keys read from URL search params:
// tenant, engagement, assessment, report, finding, remediation,
// policy, decision, timelinePosition, framework, control, evidence,
// customer, simulation, replay

/**
 * Hook that reads workspace context from URL search params.
 * Must be used within a Suspense boundary (Next.js App Router requirement).
 */
export function useWorkspaceContext(): WorkspaceContext {
  const searchParams = useSearchParams();
  const ctx: WorkspaceContext = {};

  for (const key of WORKSPACE_CONTEXT_KEYS) {
    const value = searchParams.get(key);
    if (value !== null && value !== '') {
      ctx[key] = value;
    }
  }

  // Explicit key mapping for type safety and IDE discoverability:
  // tenant · engagement · assessment · report · finding · remediation
  // policy · decision · timelinePosition · framework · control · evidence
  // customer · simulation · replay

  return ctx;
}

/**
 * Construct a URL with workspace context params appended.
 * Omits undefined/empty values. Delegates to the server-safe lib function.
 */
export function buildWorkspaceUrl(base: string, context: WorkspaceContext): string {
  return libBuildWorkspaceUrl(base, context);
}

/**
 * Default export: a render-nothing bridge component.
 * Useful when a component tree needs to opt in to context reading
 * without a visible UI wrapper.
 */
export default function WorkspaceContextBridge({
  children,
}: {
  children?: React.ReactNode;
}) {
  return <>{children}</>;
}
