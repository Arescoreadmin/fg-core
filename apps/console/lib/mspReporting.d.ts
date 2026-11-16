import type { BadgeTone, BuildResult } from './mspConsole';

export interface ShareLike {
  party?: 'customer' | 'msp';
  status?: string;
  access?: { state: string; blockers: string[] };
}

export interface ReportLike {
  report_id: string;
  manifest_hash: string;
  share_eligible: boolean;
}

export interface ShareGroup<T> {
  id: string;
  title: string;
  items: T[];
}

export type ShareAction = 'approve' | 'reject' | 'revoke' | 'withdraw' | 'verify' | 'download';

export const MAX_SHARE_DAYS: number;
export const DEFAULT_SHARE_DAYS: number;
export const SHARE_GROUPS: readonly { id: string; title: string }[];
export const LIFECYCLE_FACTS: readonly { id: string; label: string }[];
export function shareStatusView(share: ShareLike | null | undefined): { label: string; tone: BadgeTone };
export function blockerLabel(code: string): string;
export function integrityView(value: string): { label: string; tone: BadgeTone };
export function signatureKindLabel(kind: string): string;
export function lifecycleFacts(
  lifecycle: Record<string, unknown> | null | undefined,
): { id: string; label: string; value: boolean }[];
export function nextActionLabel(action: { owner: string; code: string } | null | undefined): string;
export function shareGroup(share: ShareLike): string;
export function groupShares<T extends ShareLike>(items: T[]): ShareGroup<T>[];
export function shareActions(share: ShareLike | null | undefined): ShareAction[];
export function shortHash(hash: string | null | undefined): string;
export function newShareKey(prefix?: string): string;
export function buildShareBody(input: {
  relationshipId: string;
  report: ReportLike | null | undefined;
  days: number;
  requestKey: string;
  now?: number;
}): BuildResult<{
  relationship_id: string;
  report_id: string;
  manifest_hash: string;
  expires_at: string;
  request_key: string;
}>;
export function buildApprovalBody(input: {
  report: ReportLike | null | undefined;
  days: number;
  now?: number;
}): BuildResult<{ report_id: string; manifest_hash: string; expires_at: string }>;
export function safeReportingError(
  result: { ok: boolean; status?: number; code?: string; blockers?: string[] } | null | undefined,
): string;
export function downloadFilename(doc: { engagement_id?: unknown; version?: unknown } | null | undefined): string;
