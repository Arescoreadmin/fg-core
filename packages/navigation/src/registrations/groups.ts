import type { NavigationGroupDefinition } from '../types';

export const ALL_GROUPS: NavigationGroupDefinition[] = [
  {
    id: 'Operations',
    label: 'Operations',
    description:
      'Real-time situational awareness — command center dashboards and control-plane monitoring for active AI deployments.',
    platform: 'console',
    reserved: false,
  },
  {
    id: 'Governance',
    label: 'Governance',
    description:
      'Policy authoring, provider configuration, readiness assessment, and field engagement management for AI governance programs.',
    platform: 'console',
    reserved: false,
  },
  {
    id: 'Intelligence',
    label: 'Intelligence',
    description:
      'AI workspace, knowledge corpus management, retrieval configuration, and workforce analytics for continuous intelligence.',
    platform: 'console',
    reserved: false,
  },
  {
    id: 'Trust',
    label: 'Trust',
    description:
      'Provenance tracing, decision lineage, and forensic audit capabilities that establish and sustain AI system trust.',
    platform: 'console',
    reserved: false,
  },
  {
    id: 'Compliance',
    label: 'Compliance',
    description:
      'Evaluation lab for model quality benchmarking and compliance evidence generation across regulated frameworks.',
    platform: 'console',
    reserved: false,
  },
  {
    id: 'Enterprise',
    label: 'Enterprise',
    description:
      'Reserved enterprise workspace — future multi-tenant federation, cross-org benchmarking, and executive intelligence hub.',
    platform: 'console',
    reserved: true,
  },
  {
    id: 'Administration',
    label: 'Administration',
    description:
      'Client tenant management, API key lifecycle, and platform-wide settings shared across console and portal.',
    platform: 'both',
    reserved: false,
  },
  {
    id: 'Portal',
    label: 'Portal',
    description:
      'Customer-facing portal providing engagement oversight, findings review, reporting, and remediation tracking.',
    platform: 'portal',
    reserved: false,
  },
];
