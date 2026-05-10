'use client';

import { useMemo, useState } from 'react';
import { AlertTriangle, Download, Loader2, Search } from 'lucide-react';
import {
  exportAuditEvents,
  fetchAuditEvents,
  type AuditEvent,
  type AuditSearchParams,
} from '@/lib/api';
import { AuditTimeline } from '@/components/governance';
import type { TimelineEvent } from '@/components/governance';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/cn';

function auditEventToTimeline(ev: AuditEvent): TimelineEvent {
  const summary = [ev.resource_type, ev.resource_id].filter(Boolean).join(' ') || undefined;
  return {
    id: ev.id,
    ts: ev.ts,
    actor: ev.actor ?? undefined,
    action: ev.action,
    status: ev.status,
    summary,
    requestId: ev.request_id ?? undefined,
  };
}

function statusBadgeVariant(status: string): 'success' | 'danger' | 'secondary' {
  if (status === 'success') return 'success';
  if (status === 'deny' || status === 'error') return 'danger';
  return 'secondary';
}

const DEFAULT_PAGE_SIZE = 100;

export default function AuditPage() {
  const [tenantId, setTenantId] = useState('');
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [status, setStatus] = useState('');
  const [fromTs, setFromTs] = useState('');
  const [toTs, setToTs] = useState('');
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'table' | 'timeline'>('table');

  const toIsoString = (value: string) =>
    value ? new Date(value).toISOString() : undefined;

  const params: AuditSearchParams = useMemo(
    () => ({
      tenantId: tenantId || undefined,
      action: action || undefined,
      actor: actor || undefined,
      status: status || undefined,
      fromTs: toIsoString(fromTs),
      toTs: toIsoString(toTs),
      pageSize,
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [tenantId, action, actor, status, fromTs, toTs, pageSize],
  );

  const isTenantValid = Boolean(tenantId);

  const handleSearch = async () => {
    setError(null);
    setLoading(true);
    try {
      const data = await fetchAuditEvents(params);
      setEvents(data.items || []);
      setNextCursor(data.next_cursor || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit events');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadMore = async () => {
    if (!nextCursor) return;
    setError(null);
    setLoading(true);
    try {
      const data = await fetchAuditEvents({ ...params, cursor: nextCursor });
      setEvents((prev) => [...prev, ...(data.items || [])]);
      setNextCursor(data.next_cursor || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load more events');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    setError(null);
    try {
      const blob = await exportAuditEvents({ ...params, format });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `audit-events.${format}`;
      anchor.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export audit data');
    }
  };

  const failureCount = events.filter((e) => e.status !== 'success').length;
  const canaryCount = events.filter((e) =>
    e.action.toLowerCase().startsWith('canary'),
  ).length;

  return (
    <div className="flex flex-col">
      <TopBar
        title="Audit Log"
        subtitle="Search and export tenant-scoped audit events"
        actions={
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => void handleExport('csv')}
              disabled={!isTenantValid}
            >
              <Download className="h-3.5 w-3.5" /> CSV
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => void handleExport('json')}
              disabled={!isTenantValid}
            >
              <Download className="h-3.5 w-3.5" /> JSON
            </Button>
          </div>
        }
      />

      <div className="p-6 space-y-5">
        {/* Filters */}
        <Card>
          <CardContent className="pt-5">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
              <div className="space-y-1.5">
                <Label className="text-xs uppercase tracking-wide text-muted">Tenant ID</Label>
                <Input
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  placeholder="tenant-id"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs uppercase tracking-wide text-muted">Action</Label>
                <Input
                  value={action}
                  onChange={(e) => setAction(e.target.value)}
                  placeholder="auth_success"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs uppercase tracking-wide text-muted">Actor</Label>
                <Input
                  value={actor}
                  onChange={(e) => setActor(e.target.value)}
                  placeholder="user-123"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs uppercase tracking-wide text-muted">Status</Label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="flex h-10 w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
                >
                  <option value="">Any</option>
                  <option value="success">Success</option>
                  <option value="deny">Deny</option>
                  <option value="error">Error</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs uppercase tracking-wide text-muted">From</Label>
                <Input
                  type="datetime-local"
                  value={fromTs}
                  onChange={(e) => setFromTs(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs uppercase tracking-wide text-muted">To</Label>
                <Input
                  type="datetime-local"
                  value={toTs}
                  onChange={(e) => setToTs(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs uppercase tracking-wide text-muted">Page size</Label>
                <Input
                  type="number"
                  min={1}
                  max={1000}
                  value={pageSize}
                  onChange={(e) => setPageSize(Number(e.target.value))}
                />
              </div>
            </div>
            <div className="mt-4 flex items-center gap-3">
              <Button
                className="gap-1.5"
                onClick={() => void handleSearch()}
                disabled={!isTenantValid || loading}
                loading={loading}
              >
                <Search className="h-3.5 w-3.5" /> Search
              </Button>
              {!isTenantValid && (
                <p className="text-xs text-muted">Enter a Tenant ID to search or export.</p>
              )}
            </div>
          </CardContent>
        </Card>

        {error && (
          <div className="flex items-center gap-2 rounded border border-danger/30 bg-danger/5 px-4 py-3 text-sm text-danger">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {/* Results */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="flex items-center gap-2 text-sm">
                Results
                <span className="text-xs font-normal text-muted">
                  ({events.length} event{events.length !== 1 ? 's' : ''})
                </span>
              </CardTitle>
              <div className="flex items-center gap-4">
                {events.length > 0 && (
                  <div className="hidden sm:flex gap-4 text-xs text-muted">
                    <span>
                      Failures:{' '}
                      <span className="font-medium text-foreground">{failureCount}</span>
                    </span>
                    <span>
                      Canary trips:{' '}
                      <span className="font-medium text-foreground">{canaryCount}</span>
                    </span>
                  </div>
                )}
                <div className="flex overflow-hidden rounded border border-border">
                  {(['table', 'timeline'] as const).map((v) => (
                    <button
                      key={v}
                      onClick={() => setView(v)}
                      className={cn(
                        'px-3 py-1 text-xs font-medium capitalize',
                        view === v
                          ? 'bg-primary text-white'
                          : 'bg-transparent text-muted hover:text-foreground',
                      )}
                    >
                      {v}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </CardHeader>

          <CardContent className="p-0">
            {view === 'timeline' ? (
              <div className="p-4">
                {events.length === 0 ? (
                  <p className="py-6 text-center text-sm text-muted">
                    No audit events loaded.
                  </p>
                ) : (
                  <AuditTimeline events={events.map(auditEventToTimeline)} />
                )}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      {[
                        'Time',
                        'Tenant',
                        'Actor',
                        'Action',
                        'Status',
                        'Request',
                        'Resource',
                        'IP',
                        'User Agent',
                      ].map((h) => (
                        <th
                          key={h}
                          className="whitespace-nowrap px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-muted"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {loading && events.length === 0 ? (
                      <tr>
                        <td
                          colSpan={9}
                          className="px-4 py-10 text-center text-sm text-muted"
                        >
                          <span className="flex items-center justify-center gap-2">
                            <Loader2 className="h-4 w-4 animate-spin" /> Loading…
                          </span>
                        </td>
                      </tr>
                    ) : events.length === 0 ? (
                      <tr>
                        <td
                          colSpan={9}
                          className="px-4 py-10 text-center text-sm text-muted"
                        >
                          No audit events loaded — run a search to view results.
                        </td>
                      </tr>
                    ) : (
                      events.map((event) => (
                        <tr
                          key={`${event.id}-${event.ts}`}
                          className="border-b border-border last:border-0 transition-colors hover:bg-surface-2"
                        >
                          <td className="whitespace-nowrap px-4 py-3 text-xs text-muted">
                            {event.ts}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-muted">
                            {event.tenant_id}
                          </td>
                          <td className="px-4 py-3 text-xs text-muted">
                            {event.actor || '—'}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-foreground">
                            {event.action}
                          </td>
                          <td className="px-4 py-3">
                            <Badge
                              variant={statusBadgeVariant(event.status)}
                              className="text-[10px]"
                            >
                              {event.status}
                            </Badge>
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-muted">
                            {event.request_id || '—'}
                          </td>
                          <td className="px-4 py-3 text-xs text-muted">
                            {[event.resource_type, event.resource_id]
                              .filter(Boolean)
                              .join(' ') || '—'}
                          </td>
                          <td className="px-4 py-3 text-xs text-muted">
                            {event.ip || '—'}
                          </td>
                          <td className="max-w-[180px] truncate px-4 py-3 text-xs text-muted">
                            {event.user_agent || '—'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {nextCursor && (
              <div className="border-t border-border p-4">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void handleLoadMore()}
                  disabled={loading}
                  loading={loading}
                >
                  Load more
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
