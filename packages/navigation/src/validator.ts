import type { NavigationValidationError } from './types';
import type { NavigationRegistry } from './registry';

const RESERVED_GROUPS = new Set(['Enterprise']);

export class NavigationValidator {
  constructor(private readonly registry: NavigationRegistry) {}

  /**
   * Runs all validation checks and returns the full list of errors found.
   * An empty array means the registry is valid.
   */
  validate(): NavigationValidationError[] {
    return [
      ...this.checkNoDuplicateIds(),
      ...this.checkNoDuplicateRoutes(),
      ...this.checkAllItemsHaveRoles(),
      ...this.checkAllItemsHaveMetadata(),
      ...this.checkBreadcrumbGraph(),
      ...this.checkGroupCoverage(),
    ];
  }

  checkNoDuplicateIds(): NavigationValidationError[] {
    const errors: NavigationValidationError[] = [];
    const seen = new Set<string>();

    for (const item of this.registry.getAllItems()) {
      if (seen.has(item.id)) {
        errors.push({
          type: 'DUPLICATE_ID',
          message: `Duplicate navigation item ID "${item.id}".`,
          itemId: item.id,
        });
      }
      seen.add(item.id);
    }

    return errors;
  }

  checkNoDuplicateRoutes(): NavigationValidationError[] {
    const errors: NavigationValidationError[] = [];
    const seen = new Map<string, string>(); // route → first itemId

    for (const item of this.registry.getAllItems()) {
      const existing = seen.get(item.route);
      if (existing !== undefined) {
        errors.push({
          type: 'DUPLICATE_ROUTE',
          message: `Route "${item.route}" is registered by both "${existing}" and "${item.id}".`,
          itemId: item.id,
        });
      } else {
        seen.set(item.route, item.id);
      }
    }

    return errors;
  }

  checkAllItemsHaveRoles(): NavigationValidationError[] {
    const errors: NavigationValidationError[] = [];

    for (const item of this.registry.getAllItems()) {
      if (item.roles.length === 0) {
        errors.push({
          type: 'EMPTY_ROLES',
          message: `Navigation item "${item.id}" has no roles assigned. At least one role is required.`,
          itemId: item.id,
        });
      }
    }

    return errors;
  }

  checkAllItemsHaveMetadata(): NavigationValidationError[] {
    const errors: NavigationValidationError[] = [];

    for (const item of this.registry.getAllItems()) {
      if (item.metadata.mcimId.trim() === '') {
        errors.push({
          type: 'MISSING_MCIM_ID',
          message: `Navigation item "${item.id}" has an empty mcimId in its metadata.`,
          itemId: item.id,
        });
      }
      if (item.metadata.capability.trim() === '') {
        errors.push({
          type: 'MISSING_CAPABILITY',
          message: `Navigation item "${item.id}" has an empty capability in its metadata.`,
          itemId: item.id,
        });
      }
    }

    return errors;
  }

  checkBreadcrumbGraph(): NavigationValidationError[] {
    const errors: NavigationValidationError[] = [];
    const MAX_HOPS = 20;

    for (const item of this.registry.getAllItems()) {
      if (item.breadcrumbParent === undefined) {
        continue;
      }

      const visited = new Set<string>();
      let current = item;

      while (current.breadcrumbParent !== undefined) {
        if (visited.size >= MAX_HOPS) {
          errors.push({
            type: 'BREADCRUMB_CYCLE',
            message: `Breadcrumb chain starting at "${item.id}" exceeds ${MAX_HOPS} hops — possible cycle.`,
            itemId: item.id,
          });
          break;
        }

        visited.add(current.id);
        const parentId = current.breadcrumbParent;
        const parent = this.registry.getById(parentId);

        if (parent === undefined) {
          errors.push({
            type: 'BREADCRUMB_MISSING_PARENT',
            message: `Navigation item "${current.id}" references breadcrumbParent "${parentId}" which does not exist.`,
            itemId: current.id,
          });
          break;
        }

        if (visited.has(parent.id)) {
          errors.push({
            type: 'BREADCRUMB_CYCLE',
            message: `Breadcrumb cycle detected: "${parent.id}" is an ancestor of itself (chain started at "${item.id}").`,
            itemId: item.id,
          });
          break;
        }

        current = parent;
      }
    }

    return errors;
  }

  checkGroupCoverage(): NavigationValidationError[] {
    const errors: NavigationValidationError[] = [];
    const groups = this.registry.getAllGroups();

    for (const group of groups) {
      if (RESERVED_GROUPS.has(group.id) || group.reserved) {
        continue;
      }

      const items = this.registry.getByGroup(group.id);
      const nonHiddenItems = items.filter((item) => item.visibility !== 'hidden');

      if (nonHiddenItems.length === 0) {
        errors.push({
          type: 'EMPTY_GROUP',
          message: `Navigation group "${group.id}" has no visible items. Add at least one non-hidden item or mark the group as reserved.`,
        });
      }
    }

    return errors;
  }
}
