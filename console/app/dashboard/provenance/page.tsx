import { GitBranch } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';

export default function ProvenancePage() {
  return (
    <div className="flex flex-col">
      <TopBar title="Provenance" subtitle="Source attribution and citation validation" />
      <div className="p-6">
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-10 text-center"
              aria-label="module-not-configured"
            >
              <GitBranch className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Provenance module not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                This module will provide provenance explorer workflows, citation validation
                status, and source attribution evidence for AI-generated responses.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
