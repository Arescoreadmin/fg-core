export const WORKSPACE_INTEGRATION_VERSION = '18.6.8';

export { default as WorkspaceMetadata } from './WorkspaceMetadata';
export { default as CrossWorkspaceNav } from './CrossWorkspaceNav';
export { default as WorkspaceContextBridge } from './WorkspaceContextBridge';
export { useWorkspaceContext, buildWorkspaceUrl } from './WorkspaceContextBridge';
export { default as WorkspaceEmptyState } from './WorkspaceEmptyState';
export { default as WorkspaceLoadingState } from './WorkspaceLoadingState';
export { default as DemoModeIndicator } from './DemoModeIndicator';
export { default as WorkspaceSearch } from './WorkspaceSearch';
export type { WorkspaceContext, WorkspaceLink } from './WorkspaceContextBridge';
