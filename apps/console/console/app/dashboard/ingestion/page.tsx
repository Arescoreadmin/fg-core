import { Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { DocumentIngestionConsole } from '@/components/governance';

export default function IngestionPage() {
  return (
    <div className="flex flex-col" aria-label="ingestion-page">
      <TopBar
        title="Document Ingestion"
        subtitle="Upload, track, and inspect document ingestion lifecycle"
      />
      <div className="space-y-4 p-6">

        <div className="flex items-center gap-2">
          <Upload className="h-5 w-5 text-primary" aria-hidden="true" />
          <div>
            <h1 className="text-sm font-semibold text-foreground">
              Document Ingestion Console
            </h1>
            <p className="text-xs text-muted">
              Upload documents to a corpus and monitor deterministic ingestion
              lifecycle state. No fabricated progress — all state reflects actual
              backend truth.
            </p>
          </div>
        </div>

        <Card aria-label="document-ingestion-console-card">
          <CardHeader className="pb-2">
            <h2 className="text-xs font-semibold text-foreground">
              Upload &amp; Ingestion Workflow
            </h2>
            <p className="text-[10px] text-muted">
              Select a corpus, drop or select files (.txt, .md), and monitor
              ingestion lifecycle, chunk counts, and embedding state. Failures,
              duplicates, and quarantined documents are always visible.
            </p>
          </CardHeader>
          <CardContent>
            <DocumentIngestionConsole />
          </CardContent>
        </Card>

        <Card aria-label="ingestion-capability-overview">
          <CardContent className="pt-4">
            <h2 className="mb-3 text-xs font-semibold text-foreground">
              Ingestion Console Capabilities
            </h2>
            <ul className="space-y-2 text-xs text-muted" aria-label="ingestion-capability-list">
              {[
                'Upload flow: drag-and-drop or click-to-select; .txt and .md supported',
                'Corpus targeting: operator selects target corpus; cross-tenant upload is impossible',
                'Ingestion lifecycle: received to validating to chunking to embedding to indexed',
                'Failure visibility: failed, quarantined, and duplicate states always shown',
                'Chunking visibility: active chunk count, total chunk count, superseded chunks',
                'Embedding state: pending, processing, completed, failed, skipped — no raw vectors',
                'Audit summary: document ID, version ID, source hash prefix — export-safe',
                'Resumable UX: reload page and re-query ingestion state from backend',
                'Future hooks: connector ingestion, batch, delta sync — clearly marked unavailable',
              ].map((item) => (
                <li key={item} className="flex items-start gap-1.5">
                  <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary/40" aria-hidden="true" />
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
