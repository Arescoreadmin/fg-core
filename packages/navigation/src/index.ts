// Types
export type {
  NavigationTier,
  NavigationLifecycle,
  NavigationFamily,
  NavigationGroup,
  NavigationRole,
  RouteClassification,
  NavigationVisibility,
  NavigationMaturity,
  NavigationPlatform,
  NavigationMetadata,
  NavigationItem,
  NavigationGroupDefinition,
  NavigationBreadcrumb,
  NavigationSearchResult,
  NavigationContext,
  NavigationValidationError,
  NavigationCapability,
} from './types';

// Registry
export { NavigationRegistry } from './registry';

// Resolver
export { NavigationResolver } from './resolver';

// Breadcrumbs
export { NavigationBreadcrumbResolver } from './breadcrumbs';

// Search
export { NavigationSearchIndex } from './search';

// Validator
export { NavigationValidator } from './validator';

// Context (React — 'use client' module)
export type { NavigationContextValue, NavigationProviderProps } from './context';
export { NavigationProvider, useNavigation } from './context';

// Registrations
export { CONSOLE_REGISTRY } from './registrations/console';
export { PORTAL_REGISTRY } from './registrations/portal';
export { ALL_GROUPS } from './registrations/groups';
