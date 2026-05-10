'use client';

import { useEffect, useMemo, useState } from 'react';
import { Check, Copy, Plus, RotateCw, Trash2 } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  ApiKeyCreateResponse,
  ApiKeyInfo,
  ApiKeyRotateResponse,
  createApiKey,
  fetchApiKeys,
  revokeApiKey,
  rotateApiKey,
} from '@/lib/api';

const DEFAULT_TENANT = 'default';

function formatTimestamp(value?: string | number | null): string {
  if (value === null || value === undefined || value === '') return '—';
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        void navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
      className="ml-2 shrink-0 rounded p-1 text-muted hover:text-foreground transition-colors"
      aria-label="Copy to clipboard"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-success" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </button>
  );
}

export default function KeysPage() {
  const [tenantId, setTenantId] = useState(DEFAULT_TENANT);
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createdKey, setCreatedKey] = useState<ApiKeyCreateResponse | null>(null);
  const [rotatedKey, setRotatedKey] = useState<ApiKeyRotateResponse | null>(null);
  const [formName, setFormName] = useState('');
  const [formScopes, setFormScopes] = useState('keys:read');
  const [formTtl, setFormTtl] = useState(86400);

  const ttlHours = useMemo(() => Math.round(formTtl / 3600), [formTtl]);

  async function loadKeys() {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchApiKeys(tenantId);
      setKeys(response.keys ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load keys');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadKeys();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  async function handleCreate() {
    setError(null);
    try {
      const scopes = formScopes
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const response = await createApiKey({
        name: formName || undefined,
        scopes,
        tenant_id: tenantId,
        ttl_seconds: formTtl,
      });
      setCreatedKey(response);
      setRotatedKey(null);
      setShowCreate(false);
      setFormName('');
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create key');
    }
  }

  async function handleRotate(prefix: string) {
    setError(null);
    try {
      const response = await rotateApiKey(prefix, tenantId, formTtl);
      setRotatedKey(response);
      setCreatedKey(null);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to rotate key');
    }
  }

  async function handleRevoke(prefix: string) {
    if (!window.confirm(`Revoke key ${prefix}? Active requests using this key will fail immediately.`)) return;
    setError(null);
    try {
      await revokeApiKey(prefix, tenantId);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke key');
    }
  }

  const activeKeys = keys.filter((k) => k.enabled);
  const revokedKeys = keys.filter((k) => !k.enabled);

  return (
    <div className="flex flex-col">
      <TopBar
        title="API Keys"
        subtitle="Manage tenant-scoped API keys"
        actions={
          <Button size="sm" className="gap-1.5" onClick={() => setShowCreate(true)}>
            <Plus className="h-3.5 w-3.5" /> Create Key
          </Button>
        }
      />

      <div className="p-6 space-y-5">
        {/* Tenant + TTL controls */}
        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wide text-muted">Tenant</Label>
            <Input
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              className="w-56"
              placeholder="default"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs uppercase tracking-wide text-muted">Default TTL for rotate</Label>
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={60}
                value={formTtl}
                onChange={(e) => setFormTtl(Number(e.target.value))}
                className="w-36"
              />
              <span className="text-xs text-muted whitespace-nowrap">~{ttlHours}h</span>
            </div>
          </div>
        </div>

        {error && (
          <div className="rounded border border-danger/30 bg-danger/5 px-4 py-3 text-sm text-danger">
            {error}
          </div>
        )}

        {createdKey && (
          <Card className="border-success/30 bg-success/5">
            <CardContent className="pt-4">
              <p className="mb-2 text-sm font-semibold text-success">
                Key created — copy now, this will only be shown once
              </p>
              <div className="flex items-center rounded border border-border bg-background px-3 py-2">
                <code className="flex-1 overflow-x-auto text-xs font-mono text-foreground">
                  {createdKey.key}
                </code>
                <CopyButton text={createdKey.key} />
              </div>
            </CardContent>
          </Card>
        )}

        {rotatedKey && (
          <Card className="border-success/30 bg-success/5">
            <CardContent className="pt-4">
              <p className="mb-2 text-sm font-semibold text-success">
                Key rotated — old key revoked: {rotatedKey.old_key_revoked ? 'yes' : 'no'}
              </p>
              <div className="flex items-center rounded border border-border bg-background px-3 py-2">
                <code className="flex-1 overflow-x-auto text-xs font-mono text-foreground">
                  {rotatedKey.new_key}
                </code>
                <CopyButton text={rotatedKey.new_key} />
              </div>
            </CardContent>
          </Card>
        )}

        {/* Keys table */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">
              {loading ? 'Loading…' : `${activeKeys.length} active key${activeKeys.length !== 1 ? 's' : ''}${revokedKeys.length > 0 ? `, ${revokedKeys.length} revoked` : ''}`}
            </CardTitle>
            <CardDescription>Tenant: {tenantId}</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {['Prefix', 'Name', 'Scopes', 'Last used', 'Uses', 'Expires', 'Status', ''].map((h) => (
                      <th
                        key={h}
                        className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-muted"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan={8} className="px-4 py-10 text-center text-sm text-muted">
                        Loading keys…
                      </td>
                    </tr>
                  ) : keys.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-4 py-10 text-center text-sm text-muted">
                        No keys found for this tenant.
                      </td>
                    </tr>
                  ) : (
                    keys.map((key) => (
                      <tr
                        key={key.prefix}
                        className="border-b border-border last:border-0 hover:bg-surface-2 transition-colors"
                      >
                        <td className="px-4 py-3 font-mono text-xs text-foreground">{key.prefix}</td>
                        <td className="px-4 py-3 text-muted">{key.name || '—'}</td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {key.scopes && key.scopes.length > 0
                              ? key.scopes.map((s) => (
                                  <Badge key={s} variant="secondary" className="text-[10px]">
                                    {s}
                                  </Badge>
                                ))
                              : <span className="text-muted text-xs">—</span>}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted whitespace-nowrap">
                          {formatTimestamp(key.last_used_at)}
                        </td>
                        <td className="px-4 py-3 text-muted">{key.use_count ?? 0}</td>
                        <td className="px-4 py-3 text-xs text-muted whitespace-nowrap">
                          {formatTimestamp(key.expires_at)}
                        </td>
                        <td className="px-4 py-3">
                          <Badge
                            variant={key.enabled ? 'success' : 'danger'}
                            className="text-[10px]"
                          >
                            {key.enabled ? 'Active' : 'Revoked'}
                          </Badge>
                        </td>
                        <td className="px-4 py-3">
                          {key.enabled && (
                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 gap-1 text-xs"
                                onClick={() => void handleRotate(key.prefix)}
                              >
                                <RotateCw className="h-3 w-3" /> Rotate
                              </Button>
                              <Button
                                size="sm"
                                variant="destructive"
                                className="h-7 gap-1 text-xs"
                                onClick={() => void handleRevoke(key.prefix)}
                              >
                                <Trash2 className="h-3 w-3" /> Revoke
                              </Button>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Create key modal */}
      {showCreate && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md rounded-xl border border-border bg-surface p-6 shadow-2xl space-y-4">
            <h2 className="text-base font-semibold text-foreground">Create API Key</h2>

            <div className="space-y-1.5">
              <Label>Name</Label>
              <Input
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="Production ingestion key"
              />
            </div>

            <div className="space-y-1.5">
              <Label>
                Scopes{' '}
                <span className="font-normal text-muted">(comma-separated)</span>
              </Label>
              <Input
                value={formScopes}
                onChange={(e) => setFormScopes(e.target.value)}
                placeholder="keys:read,decisions:write"
              />
            </div>

            <div className="space-y-1.5">
              <Label>TTL (seconds)</Label>
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={60}
                  value={formTtl}
                  onChange={(e) => setFormTtl(Number(e.target.value))}
                />
                <span className="text-xs text-muted whitespace-nowrap">~{ttlHours}h</span>
              </div>
            </div>

            {error && (
              <p className="rounded border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger">
                {error}
              </p>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
              <Button onClick={() => void handleCreate()}>Create Key</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
