import type { NavigationBreadcrumb } from './types';
import type { NavigationRegistry } from './registry';

const MAX_HOPS = 20;

export class NavigationBreadcrumbResolver {
  constructor(private readonly registry: NavigationRegistry) {}

  /**
   * Walks the breadcrumbParent chain from the item at `route` up to the root,
   * then reverses the result so crumbs are ordered root → leaf.
   *
   * Stops after MAX_HOPS to break cycles and returns whatever partial chain
   * was accumulated before the cycle was detected.
   */
  resolve(route: string): NavigationBreadcrumb[] {
    const item = this.registry.getByRoute(route);
    if (item === undefined) {
      return [];
    }

    const chain: NavigationBreadcrumb[] = [];
    const seen = new Set<string>();
    let current = item;

    while (true) {
      if (seen.has(current.id) || chain.length >= MAX_HOPS) {
        // Cycle detected or depth limit reached — return partial chain
        break;
      }
      seen.add(current.id);
      chain.push({ title: current.title, route: current.route, id: current.id });

      if (current.breadcrumbParent === undefined) {
        break;
      }

      const parent = this.registry.getById(current.breadcrumbParent);
      if (parent === undefined) {
        // Parent ID is registered but item doesn't exist — stop here
        break;
      }
      current = parent;
    }

    return chain.reverse();
  }

  /**
   * Same as `resolve` but replaces `[id]` path segments in routes with the
   * provided `id` value, and replaces `[id]` in titles with `label`.
   *
   * Useful for dynamic routes such as `/console/models/[id]`.
   */
  resolveWithDynamicId(route: string, id: string, label: string): NavigationBreadcrumb[] {
    const crumbs = this.resolve(route);
    return crumbs.map((crumb) => ({
      id: crumb.id,
      title: crumb.title.replace(/\[id\]/g, label),
      route: crumb.route.replace(/\[id\]/g, id),
    }));
  }
}
