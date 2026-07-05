'use client';

const MCIM_ID = 'MCIM-18.6-WS-METADATA';
const AUTHORITY = 'Workspace Metadata Authority';

interface WorkspaceMetadataProps {
  mcimId: string;
  authority: string;
  capability: string;
  workspace: string;
  sourceOfTruth: string;
  drillDown?: string;
  refreshPolicy?: 'real-time' | 'on-demand' | 'cached-60s' | 'snapshot';
  confidenceSource?: string;
  lastUpdated?: string;
}

export default function WorkspaceMetadata({
  mcimId,
  authority,
  capability,
  workspace,
  sourceOfTruth,
  drillDown,
  refreshPolicy = 'on-demand',
  confidenceSource,
  lastUpdated,
}: WorkspaceMetadataProps) {
  return (
    <>
      <div
        data-workspace-metadata="true"
        data-mcim-id={mcimId}
        data-authority={authority}
        data-capability={capability}
        data-workspace={workspace}
        data-source-of-truth={sourceOfTruth}
        data-drill-down={drillDown}
        data-refresh-policy={refreshPolicy}
        data-confidence-source={confidenceSource}
        data-last-updated={lastUpdated}
        style={{ display: 'none' }}
        aria-hidden="true"
      />
      <span
        role="presentation"
        aria-hidden="true"
        data-workspace-identity={workspace}
        data-mcim-version="18.6.8"
        style={{ display: 'none' }}
      />
    </>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
