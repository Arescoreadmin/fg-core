import { FlaskConical } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';

export default function EvaluationPage() {
  return (
    <div className="flex flex-col">
      <TopBar title="Evaluation Lab" subtitle="AI response quality and policy evaluation tooling" />
      <div className="p-6">
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-10 text-center"
              aria-label="module-not-configured"
            >
              <FlaskConical className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Evaluation Lab not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                This module will provide evaluation tooling for testing AI response quality,
                policy enforcement behavior, and retrieval accuracy against governed benchmarks.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
