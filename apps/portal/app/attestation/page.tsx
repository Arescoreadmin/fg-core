'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  portalApi,
  PortalApiError,
  type GovernanceAsset,
  type AttestationRecord,
  type SubmitAttestationPayload,
} from '@/lib/portalApi';
import {
  saveAttestationDraft,
  loadAttestationDraft,
  clearAttestationDraft,
} from '@/lib/attestationDrafts';

const RISK_CLASS: Record<string, string> = {
  critical: 'text-red-300',
  high: 'text-orange-300',
  medium: 'text-amber-200',
  low: 'text-blue-300',
};

const ATTESTATION_TYPES = [
  { value: 'compliance_review', label: 'Compliance Review' },
  { value: 'security_assessment', label: 'Security Assessment' },
  { value: 'data_classification', label: 'Data Classification' },
  { value: 'access_review', label: 'Access Review' },
  { value: 'risk_acceptance', label: 'Risk Acceptance' },
];

function RiskTierBadge({ tier }: { tier: string }) {
  const cls = RISK_CLASS[tier] ?? 'text-muted';
  return (
    <span className={`text-xs font-medium capitalize ${cls}`}>
      {tier.replace(/_/g, ' ')} risk
    </span>
  );
}

interface AttestationFormProps {
  asset: GovernanceAsset;
  onSuccess: () => void;
  onCancel: () => void;
}

function AttestationForm({ asset, onSuccess, onCancel }: AttestationFormProps) {
  const [ownerEmail, setOwnerEmail] = useState('');
  const [attestationType, setAttestationType] = useState('compliance_review');
  const [statement, setStatement] = useState('');
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [draftLoaded, setDraftLoaded] = useState(false);
  const autoSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    loadAttestationDraft(asset.asset_id).then((draft) => {
      if (draft) {
        setOwnerEmail(draft.ownerEmail);
        setAttestationType(draft.attestationType);
        setStatement(draft.statement);
        setNotes(draft.notes);
        setDraftLoaded(true);
      }
    });
  }, [asset.asset_id]);

  function scheduleSave(
    email: string,
    type: string,
    stmt: string,
    n: string,
  ) {
    if (autoSaveRef.current) clearTimeout(autoSaveRef.current);
    autoSaveRef.current = setTimeout(() => {
      saveAttestationDraft(asset.asset_id, {
        ownerEmail: email,
        attestationType: type,
        statement: stmt,
        notes: n,
      });
    }, 800);
  }

  function handleChange(
    field: 'email' | 'type' | 'statement' | 'notes',
    value: string,
  ) {
    const next = {
      email: ownerEmail,
      type: attestationType,
      statement,
      notes,
    };
    next[field === 'email' ? 'email' : field === 'type' ? 'type' : field] = value;
    if (field === 'email') setOwnerEmail(value);
    else if (field === 'type') setAttestationType(value);
    else if (field === 'statement') setStatement(value);
    else setNotes(value);
    scheduleSave(next.email, next.type, next.statement, next.notes);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!statement.trim() || !ownerEmail.trim()) return;
    setSubmitting(true);
    setSubmitError(null);
    const payload: SubmitAttestationPayload = {
      owner_email: ownerEmail.trim(),
      attestation_type: attestationType,
      statement: statement.trim(),
      notes: notes.trim() || undefined,
    };
    try {
      await portalApi.submitAttestation(asset.asset_id, payload);
      await clearAttestationDraft(asset.asset_id);
      onSuccess();
    } catch (err) {
      if (err instanceof PortalApiError) {
        if (err.status === 403) setSubmitError('Access denied.');
        else if (err.status === 400) setSubmitError('Invalid attestation data. Please review your input.');
        else setSubmitError('Submission failed. Please try again.');
      } else {
        setSubmitError('Submission failed. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="space-y-4 p-4 rounded border border-border bg-surface-2"
      aria-label={`attestation-form-${asset.asset_id}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-foreground">{asset.asset_name}</p>
          <RiskTierBadge tier={asset.risk_tier} />
        </div>
        {draftLoaded && (
          <span className="text-xs text-amber-300 border border-amber-500/30 bg-amber-500/5 rounded px-1.5 py-0.5">
            Draft restored
          </span>
        )}
      </div>

      <div className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1" htmlFor={`email-${asset.asset_id}`}>
            Owner email <span className="text-red-400">*</span>
          </label>
          <input
            id={`email-${asset.asset_id}`}
            type="email"
            required
            value={ownerEmail}
            onChange={(e) => handleChange('email', e.target.value)}
            className="w-full rounded border border-border bg-surface-3 px-3 py-1.5 text-xs text-foreground placeholder-muted focus:outline-none focus:ring-1 focus:ring-primary/50"
            placeholder="you@organization.com"
          />
        </div>

        <div>
          <label className="block text-xs text-muted mb-1" htmlFor={`type-${asset.asset_id}`}>
            Attestation type
          </label>
          <select
            id={`type-${asset.asset_id}`}
            value={attestationType}
            onChange={(e) => handleChange('type', e.target.value)}
            className="w-full rounded border border-border bg-surface-3 px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
          >
            {ATTESTATION_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs text-muted mb-1" htmlFor={`statement-${asset.asset_id}`}>
            Attestation statement <span className="text-red-400">*</span>
          </label>
          <textarea
            id={`statement-${asset.asset_id}`}
            required
            rows={3}
            value={statement}
            onChange={(e) => handleChange('statement', e.target.value)}
            className="w-full rounded border border-border bg-surface-3 px-3 py-1.5 text-xs text-foreground placeholder-muted focus:outline-none focus:ring-1 focus:ring-primary/50 resize-y"
            placeholder="I confirm that this asset has been reviewed and meets the stated compliance requirements…"
          />
        </div>

        <div>
          <label className="block text-xs text-muted mb-1" htmlFor={`notes-${asset.asset_id}`}>
            Additional notes
          </label>
          <textarea
            id={`notes-${asset.asset_id}`}
            rows={2}
            value={notes}
            onChange={(e) => handleChange('notes', e.target.value)}
            className="w-full rounded border border-border bg-surface-3 px-3 py-1.5 text-xs text-foreground placeholder-muted focus:outline-none focus:ring-1 focus:ring-primary/50 resize-y"
            placeholder="Optional context or caveats…"
          />
        </div>
      </div>

      <p className="text-xs text-muted">
        Submissions are routed to <strong className="text-foreground">pending operator review</strong> — an assessor will finalize.
      </p>

      {submitError && (
        <p className="text-xs text-red-300">{submitError}</p>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={submitting || !statement.trim() || !ownerEmail.trim()}
          aria-busy={submitting}
          className="rounded border border-primary/50 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {submitting ? 'Submitting…' : 'Submit Attestation'}
        </button>
        <button
          type="button"
          onClick={onCancel}
          disabled={submitting}
          className="rounded border border-border bg-surface-3 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40 transition-colors"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

interface AssetRowProps {
  asset: GovernanceAsset;
}

function AssetRow({ asset }: AssetRowProps) {
  const [expanded, setExpanded] = useState(false);
  const [attestations, setAttestations] = useState<AttestationRecord[] | null>(null);
  const [attLoading, setAttLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  async function loadAttestations() {
    if (attestations !== null) return;
    setAttLoading(true);
    try {
      const result = await portalApi.listAttestations(asset.asset_id);
      setAttestations(result);
    } catch {
      setAttestations([]);
    } finally {
      setAttLoading(false);
    }
  }

  function handleExpand() {
    setExpanded((v) => {
      if (!v) loadAttestations();
      return !v;
    });
  }

  function handleSuccess() {
    setShowForm(false);
    setSubmitted(true);
    setAttestations(null);
    loadAttestations();
  }

  const isDue = asset.next_attestation_due
    ? new Date(asset.next_attestation_due) <= new Date()
    : false;

  return (
    <div className="rounded border border-border bg-surface-2 overflow-hidden">
      <div
        className="flex flex-wrap items-center gap-3 p-3 cursor-pointer hover:bg-surface-3 transition-colors"
        onClick={handleExpand}
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onKeyDown={(e) => e.key === 'Enter' && handleExpand()}
      >
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-foreground truncate">{asset.asset_name}</p>
          <p className="text-xs text-muted capitalize">{asset.asset_type.replace(/_/g, ' ')}</p>
        </div>
        <RiskTierBadge tier={asset.risk_tier} />
        {isDue && (
          <span className="text-xs border border-red-500/30 bg-red-500/5 text-red-300 rounded px-1.5 py-0.5 font-medium">
            Attestation due
          </span>
        )}
        {submitted && (
          <span className="text-xs border border-green-500/30 bg-green-500/5 text-green-300 rounded px-1.5 py-0.5">
            Submitted
          </span>
        )}
        <span className="text-muted text-sm">{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div className="px-3 pb-3 space-y-3 border-t border-border pt-3">
          {asset.last_attested_at && (
            <p className="text-xs text-muted">
              Last attested: <span className="text-foreground">{new Date(asset.last_attested_at).toLocaleDateString()}</span>
            </p>
          )}
          {asset.next_attestation_due && (
            <p className="text-xs text-muted">
              Due:{' '}
              <span className={isDue ? 'text-red-300 font-medium' : 'text-foreground'}>
                {new Date(asset.next_attestation_due).toLocaleDateString()}
              </span>
            </p>
          )}

          {!showForm && (
            <button
              className="rounded border border-primary/40 bg-primary/5 px-2.5 py-1 text-xs text-primary hover:bg-primary/10 transition-colors"
              onClick={() => setShowForm(true)}
            >
              + Submit Attestation
            </button>
          )}

          {showForm && (
            <AttestationForm
              asset={asset}
              onSuccess={handleSuccess}
              onCancel={() => setShowForm(false)}
            />
          )}

          {attLoading && (
            <div className="space-y-1.5">
              {[1, 2].map((i) => (
                <div key={i} className="h-8 rounded border border-border bg-surface-3 animate-pulse" />
              ))}
            </div>
          )}

          {!attLoading && attestations && attestations.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted mb-1.5">
                History ({attestations.length})
              </p>
              <div className="space-y-1.5">
                {attestations.slice(0, 5).map((a) => (
                  <div key={a.attestation_id} className="rounded border border-border bg-surface-3 p-2 text-xs space-y-0.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="capitalize text-foreground">{a.attestation_type.replace(/_/g, ' ')}</span>
                      <span className="text-muted">{new Date(a.attested_at).toLocaleDateString()}</span>
                    </div>
                    <p className="text-muted">{a.statement.slice(0, 120)}{a.statement.length > 120 ? '…' : ''}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!attLoading && attestations && attestations.length === 0 && (
            <p className="text-xs text-muted">No attestation history.</p>
          )}
        </div>
      )}
    </div>
  );
}

const PAGE_SIZE = 20;

export default function AttestationPage() {
  const [assets, setAssets] = useState<GovernanceAsset[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'due'>('due');

  const load = useCallback(async (offset: number) => {
    setLoading(true);
    setError(null);
    try {
      const result = await portalApi.listAssets({ limit: PAGE_SIZE, offset });
      setAssets(result);
      setTotal(result.length);
    } catch {
      setError('Failed to load assets. Please try again.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setPage(0);
    load(0);
  }, [load]);

  function handlePage(newPage: number) {
    setPage(newPage);
    load(newPage * PAGE_SIZE);
  }

  const now = new Date();
  const displayAssets =
    filter === 'due'
      ? assets.filter(
          (a) =>
            !a.next_attestation_due ||
            new Date(a.next_attestation_due) <= now,
        )
      : assets;

  const totalPages = Math.ceil(total / PAGE_SIZE);
  const dueCount = assets.filter(
    (a) => !a.next_attestation_due || new Date(a.next_attestation_due) <= now,
  ).length;

  return (
    <div className="space-y-4" aria-label="attestation-page">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-foreground">Asset Attestations</h2>
          {!loading && dueCount > 0 && (
            <p className="text-xs text-amber-300 mt-0.5">{dueCount} asset{dueCount !== 1 ? 's' : ''} due for attestation</p>
          )}
        </div>
        <div className="flex items-center gap-1 rounded border border-border overflow-hidden text-xs">
          <button
            className={`px-3 py-1 transition-colors ${filter === 'due' ? 'bg-primary/10 text-primary' : 'text-muted hover:text-foreground'}`}
            onClick={() => setFilter('due')}
          >
            Due
          </button>
          <button
            className={`px-3 py-1 transition-colors ${filter === 'all' ? 'bg-primary/10 text-primary' : 'text-muted hover:text-foreground'}`}
            onClick={() => setFilter('all')}
          >
            All
          </button>
        </div>
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {error && !loading && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      {!loading && !error && displayAssets.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center text-muted">
          <p className="text-sm font-medium">
            {filter === 'due' ? 'No assets due for attestation' : 'No assets found'}
          </p>
          {filter === 'due' && assets.length > 0 && (
            <button
              className="mt-2 text-xs text-primary hover:underline"
              onClick={() => setFilter('all')}
            >
              View all assets
            </button>
          )}
        </div>
      )}

      {!loading && displayAssets.length > 0 && (
        <>
          <div className="space-y-2">
            {displayAssets.map((a) => (
              <AssetRow key={a.asset_id} asset={a} />
            ))}
          </div>

          {filter === 'all' && totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 text-xs text-muted pt-2">
              <button
                className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
                onClick={() => handlePage(page - 1)}
                disabled={page === 0}
                aria-label="Previous page"
              >
                ‹ Prev
              </button>
              <span>{page + 1} / {totalPages}</span>
              <button
                className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed"
                onClick={() => handlePage(page + 1)}
                disabled={page >= totalPages - 1}
                aria-label="Next page"
              >
                Next ›
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
