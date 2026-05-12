import { Layers } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';

export default function RetrievalPage() {
  return (
    <div className="flex flex-col">
      <TopBar title="Retrieval" subtitle="Retrieval pipeline configuration and traces" />
      <div className="p-6">
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-10 text-center"
              aria-label="module-not-configured"
            >
              <Layers className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Retrieval module not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                This module will provide retrieval trace inspection, hybrid RRF pipeline
                visibility, and per-request chunk provenance for governed retrieval operations.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
