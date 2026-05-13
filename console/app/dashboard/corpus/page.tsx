import { Database } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { CorpusManagementConsole } from '@/components/governance';

export default function CorpusPage() {
  return (
    <div className="flex flex-col" aria-label="corpus-page">
      <TopBar title="Corpus" subtitle="Corpus management, document browsing, and ingestion visibility" />
      <div className="space-y-4 p-6">

        {/* Page header */}
        <div className="flex items-center gap-2">
          <Database className="h-5 w-5 text-primary" aria-hidden="true" />
          <div>
            <h1 className="text-sm font-semibold text-foreground">
              Corpus Management Console
            </h1>
            <p className="text-xs text-muted">
              Operator-readable corpus and document state. Data reflects actual backend
              ingestion lifecycle — no fabricated metrics.
            </p>
          </div>
        </div>

        {/* Corpus Management Console — wired to live backend */}
        <Card aria-label="corpus-management-console-card">
          <CardHeader className="pb-2">
            <h2 className="text-xs font-semibold text-foreground">
              Corpus &amp; Document Browser
            </h2>
            <p className="text-[10px] text-muted">
              Select a corpus to inspect document counts, chunk state, ingestion status,
              and embedding state. Filtering and pagination are tenant-scoped and
              deterministic. Raw vectors and prompts are not exposed.
            </p>
          </CardHeader>
          <CardContent>
            <CorpusManagementConsole />
          </CardContent>
        </Card>

        {/* Capability overview */}
        <Card aria-label="corpus-capability-overview">
          <CardContent className="pt-4">
            <h2 className="mb-3 text-xs font-semibold text-foreground">
              Corpus Console Capabilities
            </h2>
            <ul
              className="space-y-2 text-xs text-muted"
              aria-label="corpus-capability-list"
            >
              {[
                'Corpus browser: tenant-scoped corpus list with document and chunk counts',
                'Document browser: paginated document list with ingestion status and chunk counts',
                'Ingestion lifecycle badges: received, validating, chunking, embedding, indexed, failed, quarantined, superseded',
                'Embedding state visibility: pending, processing, completed, failed, skipped',
                'Filtering: by ingestion status and version state (current/superseded)',
                'Pagination: deterministic and tenant-scoped; stable sort with tiebreaker',
                'Document detail: chunk summary, embedding state distribution, source hash prefix',
                'Safe metadata viewer: no raw vectors, no prompts, no secrets exposed',
                'Quarantine and failure state always visible — no silent suppression',
                'Future hooks: connector sync, stale detection, duplicate detection (not yet active)',
              ].map((item) => (
                <li key={item} className="flex items-start gap-1.5">
                  <span
                    className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary/40"
                    aria-hidden="true"
                  />
                  {item}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

      </div>
    </div>
  );
}
