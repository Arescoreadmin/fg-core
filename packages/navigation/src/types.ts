// Navigation tier controls display prominence and routing priority
export type NavigationTier =
  | 'primary'
  | 'secondary'
  | 'contextual'
  | 'administrative'
  | 'specialist'
  | 'hidden'
  | 'legacy'
  | 'deprecated'
  | 'future'
  | 'retired';

// Lifecycle tracks the maturity stage of a navigation item over time
export type NavigationLifecycle =
  | 'core'
  | 'stable'
  | 'growing'
  | 'legacy'
  | 'future'
  | 'deprecated';

// MCIM capability families — exhaustive union of all defined families
export type NavigationFamily =
  | 'commercial-intake'
  | 'operator-execution'
  | 'trust-audit'
  | 'trust'
  | 'delivery'
  | 'closed-loop'
  | 'continuous-posture'
  | 'intelligence'
  | 'trust-explainability'
  | 'trust-forensics'
  | 'trust-center'
  | 'trust-policy'
  | 'platform-admin'
  | 'cross-platform'
  | 'platform-ops'
  | 'ai-governance'
  | 'identity-grants'
  | 'commercial-ops'
  | 'monitoring'
  | 'ai-quality'
  | 'knowledge';

// MCIM-mandated navigation groups — must use these exact strings
export type NavigationGroup =
  | 'Operations'
  | 'Governance'
  | 'Intelligence'
  | 'Trust'
  | 'Compliance'
  | 'Enterprise'
  | 'Administration'
  | 'Portal';

// Roles that can be granted access to navigation items
export type NavigationRole =
  | 'Executive'
  | 'Board'
  | 'CISO'
  | 'Compliance'
  | 'Auditor'
  | 'Operator'
  | 'AssessmentEngineer'
  | 'FieldAssessor'
  | 'Customer'
  | 'MSP'
  | 'Consultant'
  | 'Administrator'
  | 'Developer'
  | 'Support';

// Alias for NavigationTier — kept as a semantic synonym for route classification
export type RouteClassification = NavigationTier;

// Whether an item is shown in navigation UI
export type NavigationVisibility = 'visible' | 'hidden' | 'conditional';

// Maturity of the underlying capability implementation
export type NavigationMaturity =
  | 'strong'
  | 'functional'
  | 'partial'
  | 'latent'
  | 'partial-backend';

// Which application platform the item belongs to
export type NavigationPlatform = 'console' | 'portal' | 'both';

// MCIM-sourced metadata attached to every navigation item
export interface NavigationMetadata {
  mcimId: string;
  capability: string;
  family: NavigationFamily;
  authority: string;
  sourceOfTruth: string;
  maturity: NavigationMaturity;
  lifecycle: NavigationLifecycle;
  businessValue: string;
}

// The core unit of navigation — one page or feature entry point
export interface NavigationItem {
  id: string;
  title: string;
  route: string;
  group: NavigationGroup;
  tier: NavigationTier;
  classification: RouteClassification;
  visibility: NavigationVisibility;
  platform: NavigationPlatform;
  icon?: string;
  roles: NavigationRole[];
  aliases: string[];
  keywords: string[];
  breadcrumbParent?: string;
  featureFlag?: string;
  metadata: NavigationMetadata;
}

// Top-level grouping definition registered in the navigation system
export interface NavigationGroupDefinition {
  id: NavigationGroup;
  label: string;
  description: string;
  platform: NavigationPlatform;
  reserved: boolean;
}

// A single crumb in a breadcrumb trail
export interface NavigationBreadcrumb {
  title: string;
  route: string;
  id: string;
}

// A ranked result from a navigation search query
export interface NavigationSearchResult {
  item: NavigationItem;
  score: number;
  matchedField: string;
}

// Runtime context describing the current navigation state
export interface NavigationContext {
  activeRoute: string;
  activeGroup: NavigationGroup | null;
  platform: NavigationPlatform;
  roles: NavigationRole[];
}

// Structured error emitted by NavigationValidator
export interface NavigationValidationError {
  type:
    | 'DUPLICATE_ID'
    | 'DUPLICATE_ROUTE'
    | 'EMPTY_ROLES'
    | 'MISSING_MCIM_ID'
    | 'MISSING_CAPABILITY'
    | 'BREADCRUMB_CYCLE'
    | 'BREADCRUMB_MISSING_PARENT'
    | 'EMPTY_GROUP';
  message: string;
  itemId?: string;
}

// A named capability and the navigation item IDs that implement it
export interface NavigationCapability {
  name: string;
  family: NavigationFamily;
  items: string[];
}
