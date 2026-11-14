export interface DelegableCapability {
  id: string;
  label: string;
  description: string;
}

export type BadgeTone = 'success' | 'warning' | 'danger' | 'secondary' | 'outline';

export interface RelationshipLike {
  status: string;
  expires_at?: string | null;
}

export interface RelationshipCounts {
  active: number;
  pending: number;
  approved: number;
  suspended: number;
  expiring: number;
  revoked: number;
  expired: number;
}

export type RelationshipAction = 'approve' | 'suspend' | 'resume' | 'revoke';

export interface PortfolioItemLike {
  effective_permissions?: string[];
  assessment?: { state: string };
  findings?: { state: string; outstanding_total?: number };
}

export type BuildResult<T> = { ok: true; body: T } | { ok: false; error: string };

export interface ApprovalBody {
  authorized_capabilities: string[];
  expires_at: string;
}

export interface ProposalBody {
  customer_tenant_id: string;
  requested_capabilities: string[];
}

export interface ResultLike {
  ok: boolean;
  status?: number;
  code?: string;
}

export const DELEGABLE_CAPABILITIES: readonly DelegableCapability[];
export const MAX_RELATIONSHIP_DAYS: number;
export const DEFAULT_APPROVAL_DAYS: number;
export const EXPIRING_SOON_DAYS: number;
export function capabilityLabel(id: string): string;
export function statusView(status: string): { label: string; tone: BadgeTone };
export function sectionStateLabel(state: string): string;
export function isExpiringSoon(relationship: RelationshipLike, now?: number): boolean;
export function summarizeRelationships(items: RelationshipLike[], now?: number): RelationshipCounts;
export function availableActions(relationship: RelationshipLike, party: 'customer' | 'msp'): RelationshipAction[];
export function nextAction(item: PortfolioItemLike): string;
export function buildApprovalBody(input: {
  requested: string[];
  selected: string[];
  days: number;
  now?: number;
}): BuildResult<ApprovalBody>;
export function buildProposalBody(input: {
  customerTenantId: string;
  selected: string[];
}): BuildResult<ProposalBody>;
export function safeErrorMessage(result: ResultLike): string;
