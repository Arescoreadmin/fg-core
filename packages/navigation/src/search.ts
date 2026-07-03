import type {
  NavigationItem,
  NavigationPlatform,
  NavigationRole,
  NavigationSearchResult,
} from './types';
import type { NavigationRegistry } from './registry';

interface IndexEntry {
  item: NavigationItem;
  titleLower: string;
  aliasesLower: string[];
  capabilityLower: string;
  authorityLower: string;
  keywordsLower: string[];
}

const SCORE_TITLE = 10;
const SCORE_ALIAS = 7;
const SCORE_CAPABILITY = 5;
const SCORE_KEYWORD = 3;

export class NavigationSearchIndex {
  private index: IndexEntry[] = [];
  private built = false;

  constructor(private readonly registry: NavigationRegistry) {}

  /**
   * Indexes all registered items. Must be called before `search` or
   * `searchForRole`. Safe to call multiple times — rebuilds on each call.
   */
  build(): void {
    this.index = this.registry.getAllItems().map((item) => ({
      item,
      titleLower: item.title.toLowerCase(),
      aliasesLower: item.aliases.map((a) => a.toLowerCase()),
      capabilityLower: item.metadata.capability.toLowerCase(),
      authorityLower: item.metadata.authority.toLowerCase(),
      keywordsLower: item.keywords.map((k) => k.toLowerCase()),
    }));
    this.built = true;
  }

  /**
   * Case-insensitive substring search across title, aliases, capability,
   * authority, and keywords. Returns results sorted by score descending.
   *
   * @param query   The search string
   * @param platform Items are filtered to this platform ('both' items always included)
   * @param limit   Maximum results to return (default: 20)
   */
  search(
    query: string,
    platform: NavigationPlatform,
    limit = 20,
  ): NavigationSearchResult[] {
    if (!this.built) {
      this.build();
    }

    const q = query.toLowerCase().trim();
    if (q.length === 0) {
      return [];
    }

    const results: NavigationSearchResult[] = [];

    for (const entry of this.index) {
      if (entry.item.platform !== platform && entry.item.platform !== 'both') {
        continue;
      }
      const result = this.scoreEntry(entry, q);
      if (result !== null) {
        results.push(result);
      }
    }

    return results.sort((a, b) => b.score - a.score).slice(0, limit);
  }

  /**
   * Same as `search` but further filters to items accessible by `role`.
   */
  searchForRole(
    query: string,
    role: NavigationRole,
    platform: NavigationPlatform,
    limit = 20,
  ): NavigationSearchResult[] {
    return this.search(query, platform, limit * 2)
      .filter((r) => r.item.roles.includes(role))
      .slice(0, limit);
  }

  private scoreEntry(entry: IndexEntry, q: string): NavigationSearchResult | null {
    if (entry.titleLower.includes(q)) {
      return { item: entry.item, score: SCORE_TITLE, matchedField: 'title' };
    }

    for (const alias of entry.aliasesLower) {
      if (alias.includes(q)) {
        return { item: entry.item, score: SCORE_ALIAS, matchedField: 'alias' };
      }
    }

    if (entry.capabilityLower.includes(q)) {
      return { item: entry.item, score: SCORE_CAPABILITY, matchedField: 'capability' };
    }

    if (entry.authorityLower.includes(q)) {
      return { item: entry.item, score: SCORE_CAPABILITY, matchedField: 'authority' };
    }

    for (const keyword of entry.keywordsLower) {
      if (keyword.includes(q)) {
        return { item: entry.item, score: SCORE_KEYWORD, matchedField: 'keyword' };
      }
    }

    return null;
  }
}
