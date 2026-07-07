export interface ConsolePrincipal {
  experienceClass: string;
  isAuthenticated: boolean;
  roles: string[];
  explicitRoles?: string[];
  tenantId: string | null;
  unrecognizedRoles?: string[];
}

export interface ConsoleRouteAudit {
  id: string;
  title: string;
  routePattern: string;
  audience:
    | 'platform_internal'
    | 'frostgate_operator'
    | 'tenant_admin_console'
    | 'client_console_limited'
    | 'client_portal'
    | 'support_limited'
    | 'forbidden_to_clients'
    | 'unknown_needs_review';
  navVisible: boolean;
  directlyRoutable: boolean;
  allowedRoles: string[];
  backendApis: string[];
  tenantScoped: boolean;
  clientSafe: boolean;
  exposesInternalMetadata: boolean;
  readOnly: boolean;
  allowsMutation: boolean;
  exportsSanitized: boolean;
  notes?: string;
}

export interface CoreApiPolicy {
  prefix: string;
  allowedRoles: string[];
  tenantScoped: boolean;
  clientSafe: boolean;
  readOnly: boolean;
  mutationRoles?: string[];
}

export const CLIENT_CONSOLE_ROLES: string[];
export const CLIENT_MUTATION_ROLES: string[];
export const CONSOLE_ROUTE_AUDITS: ConsoleRouteAudit[];
export const CORE_API_POLICIES: CoreApiPolicy[];
export const INTERNAL_CONSOLE_ROLES: string[];
export const LEGACY_INTERNAL_ROLE: string;

export function canAccessConsoleRoute(pathname: string, source: unknown): boolean;
export function canAccessCoreApiPath(
  pathOrSegments: string | string[],
  method: string,
  source: unknown,
): boolean;
export function getConsoleRouteAudit(pathname: string): ConsoleRouteAudit | null;
export function getCoreApiPolicy(pathOrSegments: string | string[]): CoreApiPolicy | null;
export function getNavigationItemsForPrincipal<T extends { route: string; visibility: string }>(
  items: T[],
  source: unknown,
): T[];
export function getSessionClaims(source: unknown): {
  roles: string[];
  tenantId: string | null;
  experienceClass: string;
};
export function matchRoutePattern(pattern: string, pathname: string): boolean;
export function normalizePathname(pathname: string): string;
export function resolveConsolePrincipal(source: unknown): ConsolePrincipal;
