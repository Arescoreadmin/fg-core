import type {
  NavigationGroup,
  NavigationItem,
  NavigationPlatform,
  NavigationRole,
  NavigationTier,
} from './types';
import type { NavigationRegistry } from './registry';

// Numeric weight for sorting: lower = higher precedence in nav
const TIER_ORDER: Record<NavigationTier, number> = {
  primary: 0,
  secondary: 1,
  contextual: 2,
  administrative: 3,
  specialist: 4,
  hidden: 5,
  legacy: 6,
  deprecated: 7,
  future: 8,
  retired: 9,
};

function byTier(a: NavigationItem, b: NavigationItem): number {
  return TIER_ORDER[a.tier] - TIER_ORDER[b.tier];
}

export class NavigationResolver {
  constructor(private readonly registry: NavigationRegistry) {}

  /**
   * Returns a map of NavigationGroup → items sorted by tier, containing only
   * items that are visible and include the given role, filtered to the platform.
   */
  resolveForRole(
    role: NavigationRole,
    platform: NavigationPlatform,
  ): Map<NavigationGroup, NavigationItem[]> {
    const visible = this.registry.getVisibleForRole(role, platform);
    const grouped = new Map<NavigationGroup, NavigationItem[]>();

    for (const item of visible) {
      const bucket = grouped.get(item.group);
      if (bucket !== undefined) {
        bucket.push(item);
      } else {
        grouped.set(item.group, [item]);
      }
    }

    for (const [group, items] of Array.from(grouped.entries())) {
      grouped.set(group, items.slice().sort(byTier));
    }

    return grouped;
  }

  /**
   * Given a route string, returns the NavigationGroup it belongs to, or null
   * if the route is not registered.
   */
  resolveActiveGroup(route: string, platform: NavigationPlatform): NavigationGroup | null {
    const item = this.registry.getByRoute(route);
    if (item !== undefined && (item.platform === platform || item.platform === 'both')) {
      return item.group;
    }

    // Fall back to prefix matching for dynamic routes not registered verbatim
    const allItems = this.registry.getByPlatform(platform);
    let bestMatch: NavigationItem | undefined;
    let bestLength = 0;

    for (const candidate of allItems) {
      if (route.startsWith(candidate.route) && candidate.route.length > bestLength) {
        bestMatch = candidate;
        bestLength = candidate.route.length;
      }
    }

    return bestMatch !== undefined ? bestMatch.group : null;
  }

  /**
   * Returns the NavigationItem registered for a route, or undefined.
   */
  resolveItem(route: string): NavigationItem | undefined {
    return this.registry.getByRoute(route);
  }

  /**
   * All items with tier === 'primary' for the given platform, sorted by tier
   * (all are primary, so order is stable — secondary sort by title for determinism).
   */
  resolvePrimaryItems(platform: NavigationPlatform): NavigationItem[] {
    return this.registry
      .getByPlatform(platform)
      .filter((item) => item.tier === 'primary')
      .sort((a, b) => a.title.localeCompare(b.title));
  }

  /**
   * All items with tier === 'administrative' for the given platform.
   */
  resolveAdminItems(platform: NavigationPlatform): NavigationItem[] {
    return this.registry
      .getByPlatform(platform)
      .filter((item) => item.tier === 'administrative')
      .sort(byTier);
  }
}
