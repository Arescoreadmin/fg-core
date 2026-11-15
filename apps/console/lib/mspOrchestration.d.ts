import type { BadgeTone, BuildResult } from './mspConsole';

export interface AssessmentTypeOption {
  id: string;
  label: string;
}

export interface NextAction {
  owner: 'customer' | 'msp' | 'platform' | 'assessor';
  code: string;
}

export interface GrantLike {
  party?: 'customer' | 'msp';
  status?: string;
  effective_status?: string;
  blockers?: string[];
}

export interface GrantRequestBody {
  customer_tenant_id: string;
  request_key: string;
  assessment_type: string;
  assessor_id: string;
  expires_at: string;
}

export interface OnboardingBody {
  request_key: string;
  organization_name: string;
  contact_email: string;
  requested_capabilities: string[];
}

export type GrantAction = 'approve' | 'reject' | 'revoke' | 'withdraw' | 'initiate';

export const ASSESSMENT_TYPES: readonly AssessmentTypeOption[];
export const MAX_GRANT_DAYS: number;
export const DEFAULT_GRANT_DAYS: number;
export function assessmentTypeLabel(id: string): string;
export function grantStatusView(grant: GrantLike): { label: string; tone: BadgeTone };
export function blockerLabel(code: string): string;
export function nextActionLabel(action: NextAction | null | undefined): string;
export function onboardingStageView(stage: string): { label: string; tone: BadgeTone };
export function grantActions(grant: GrantLike | null | undefined): GrantAction[];
export function progressLabel(progress: { state: string; engagement_status?: string } | null | undefined): string;
export function newRequestKey(prefix?: string): string;
export function buildGrantRequestBody(input: {
  customerTenantId: string;
  assessmentType: string;
  assessorId: string;
  days: number;
  requestKey: string;
  now?: number;
}): BuildResult<GrantRequestBody>;
export function buildOnboardingBody(input: {
  organizationName: string;
  contactEmail: string;
  selected: string[];
  requestKey: string;
}): BuildResult<OnboardingBody>;
export function safeOrchestrationError(result: {
  ok: boolean;
  status?: number;
  code?: string;
} | null | undefined): string;
