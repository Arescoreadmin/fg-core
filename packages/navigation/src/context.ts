'use client';

import React from 'react';
import type { NavigationContext, NavigationGroup, NavigationPlatform, NavigationRole } from './types';
import type { NavigationRegistry } from './registry';
import type { NavigationResolver } from './resolver';
import type { NavigationSearchIndex } from './search';

// Extends the base context with live service references
export interface NavigationContextValue extends NavigationContext {
  registry: NavigationRegistry;
  resolver: NavigationResolver;
  search: NavigationSearchIndex;
}

const NavigationCtx = React.createContext<NavigationContextValue | null>(null);

export interface NavigationProviderProps {
  children: React.ReactNode;
  activeRoute: string;
  activeGroup: NavigationGroup | null;
  platform: NavigationPlatform;
  roles: NavigationRole[];
  registry: NavigationRegistry;
  resolver: NavigationResolver;
  search: NavigationSearchIndex;
}

/**
 * Provides navigation context to the component tree.
 * Must wrap any component that calls `useNavigation()`.
 */
export function NavigationProvider({
  children,
  activeRoute,
  activeGroup,
  platform,
  roles,
  registry,
  resolver,
  search,
}: NavigationProviderProps): React.JSX.Element {
  const value = React.useMemo<NavigationContextValue>(
    () => ({
      activeRoute,
      activeGroup,
      platform,
      roles,
      registry,
      resolver,
      search,
    }),
    [activeRoute, activeGroup, platform, roles, registry, resolver, search],
  );

  return React.createElement(NavigationCtx.Provider, { value }, children);
}

/**
 * Returns the current NavigationContextValue.
 * Throws if called outside a NavigationProvider.
 */
export function useNavigation(): NavigationContextValue {
  const ctx = React.useContext(NavigationCtx);
  if (ctx === null) {
    throw new Error(
      'useNavigation() must be called inside a <NavigationProvider>. ' +
        'Ensure your component tree includes NavigationProvider from @fg/navigation.',
    );
  }
  return ctx;
}
