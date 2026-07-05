'use client';
import PortalShell from './PortalShell';
import type { GovernanceAsset, AttestationRecord } from '@/lib/portalApi';

const MCIM_ID = 'MCIM-18.6-PORTAL-ATTESTATION';
const AUTHORITY = 'Customer Attestation Authority';
const sourceOfTruth = '/api/core/governance/assets';
const drillDown = '/attestation';
const customerSafe = true;

export type AttestationTab = 'required' | 'submitted' | 'pending' | 'needs-update';

interface Props {
  assets: GovernanceAsset[];
  attestations: AttestationRecord[];
  activeTab: AttestationTab;
  onTabChange?: (t: AttestationTab) => void;
  onSubmit?: (assetId: string) => void;
  loading: boolean;
  lastUpdated?: string;
}

const TABS: { id: AttestationTab; label: string }[] = [
  { id: 'required', label: 'Required' },
  { id: 'submitted', label: 'Submitted' },
  { id: 'pending', label: 'Pending' },
  { id: 'needs-update', label: 'Needs Update' },
];

const STATUS_CLASS: Record<string, string> = {
  compliant: 'border-green-500/40 bg-green-500/10 text-green-300',
  active: 'border-green-500/40 bg-green-500/10 text-green-300',
  pending_review: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  overdue: 'border-red-500/40 bg-red-500/10 text-red-300',
  due_soon: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  never_attested: 'border-border bg-surface-2 text-muted',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-2 text-muted';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, ' ')}
    </span>
  );
}

function getTabAssets(assets: GovernanceAsset[], attestations: AttestationRecord[], tab: AttestationTab) {
  const attestedAssetIds = new Set(attestations.map((a) => a.asset_id));
  switch (tab) {
    case 'required':
      return assets.filter((a) => !attestedAssetIds.has(a.asset_id));
    case 'submitted':
      return assets.filter((a) => attestedAssetIds.has(a.asset_id) && a.status === 'active');
    case 'pending':
      return assets.filter((a) => a.status === 'pending_review');
    case 'needs-update':
      return assets.filter((a) => {
        if (!a.next_attestation_due) return false;
        return new Date(a.next_attestation_due) < new Date();
      });
    default:
      return [];
  }
}

export default function AttestationCenter({
  assets,
  attestations,
  activeTab,
  onTabChange,
  onSubmit,
  loading,
  lastUpdated,
}: Props) {
  const tabAssets = getTabAssets(assets, attestations, activeTab);
  const canSubmit = !!onSubmit && (activeTab === 'required' || activeTab === 'needs-update');

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Attestation"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Attestation Center"
      lastUpdated={lastUpdated}
    >
      <section aria-label="attestation-center" data-testid="attestation-center">
      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-border pb-2">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-primary/10 text-primary border border-primary/30'
                : 'text-muted hover:text-foreground hover:bg-surface-2 border border-transparent'
            }`}
            onClick={() => onTabChange?.(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-14 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && tabAssets.length === 0 && (
        <p className="text-sm text-muted text-center py-8">
          No assets in the {activeTab.replace(/-/g, ' ')} state.
        </p>
      )}

      {!loading && tabAssets.length > 0 && (
        <div className="space-y-3">
          {canSubmit && (
            <p className="text-xs text-muted border border-border rounded px-3 py-2 bg-surface-2">
              Attestation submissions are reviewed by your engagement team before taking effect.
            </p>
          )}
          {tabAssets.map((asset) => (
            <div
              key={asset.asset_id}
              className="rounded border border-border bg-surface-2 p-3 space-y-2"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-foreground">{asset.asset_name}</span>
                <StatusBadge status={asset.status} />
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
                <span>Type: {asset.asset_type}</span>
                <span>Risk: {asset.risk_tier}</span>
                {asset.next_attestation_due && (
                  <span>Due: {new Date(asset.next_attestation_due).toLocaleDateString()}</span>
                )}
                {asset.last_attested_at && (
                  <span>Last attested: {new Date(asset.last_attested_at).toLocaleDateString()}</span>
                )}
              </div>
              {canSubmit && (
                <button
                  type="button"
                  className="rounded border border-primary/30 bg-primary/5 px-2.5 py-1 text-xs text-primary hover:bg-primary/10 transition-colors"
                  onClick={() => onSubmit?.(asset.asset_id)}
                >
                  Submit Attestation
                </button>
              )}
            </div>
          ))}
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
