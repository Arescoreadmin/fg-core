import type {
  NavigationGroup,
  NavigationGroupDefinition,
  NavigationItem,
  NavigationPlatform,
  NavigationRole,
} from './types';

export class NavigationRegistry {
  private readonly items = new Map<string, NavigationItem>();
  private readonly itemsByRoute = new Map<string, NavigationItem>();
  private readonly groups = new Map<NavigationGroup, NavigationGroupDefinition>();

  register(item: NavigationItem): void {
    if (this.items.has(item.id)) {
      throw new Error(
        `NavigationRegistry: duplicate item ID "${item.id}". Each navigation item must have a unique id.`,
      );
    }
    if (this.itemsByRoute.has(item.route)) {
      const existing = this.itemsByRoute.get(item.route)!;
      throw new Error(
        `NavigationRegistry: duplicate route "${item.route}" on item "${item.id}" — already registered by "${existing.id}".`,
      );
    }
    this.items.set(item.id, item);
    this.itemsByRoute.set(item.route, item);
  }

  registerGroup(group: NavigationGroupDefinition): void {
    this.groups.set(group.id, group);
  }

  getById(id: string): NavigationItem | undefined {
    return this.items.get(id);
  }

  getByRoute(route: string): NavigationItem | undefined {
    return this.itemsByRoute.get(route);
  }

  getAllItems(): NavigationItem[] {
    return Array.from(this.items.values());
  }

  getByGroup(group: NavigationGroup): NavigationItem[] {
    return Array.from(this.items.values()).filter((item) => item.group === group);
  }

  getByPlatform(platform: NavigationPlatform): NavigationItem[] {
    return Array.from(this.items.values()).filter(
      (item) => item.platform === platform || item.platform === 'both',
    );
  }

  getVisibleForRole(role: NavigationRole, platform: NavigationPlatform): NavigationItem[] {
    return this.getByPlatform(platform).filter(
      (item) => item.visibility !== 'hidden' && item.roles.includes(role),
    );
  }

  getAllGroups(): NavigationGroupDefinition[] {
    return Array.from(this.groups.values());
  }

  getGroupById(id: NavigationGroup): NavigationGroupDefinition | undefined {
    return this.groups.get(id);
  }

  size(): number {
    return this.items.size;
  }
}
