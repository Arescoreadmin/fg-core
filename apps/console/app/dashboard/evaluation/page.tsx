import { FlaskConical } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';
import { EvaluationLabConsole } from '@/components/governance/EvaluationLabConsole';

export default function EvaluationPage() {
  return (
    <div className="flex flex-col">
      <TopBar
        title="Evaluation Lab"
        subtitle="Operator-grade retrieval and grounding evaluation workspace"
      />
      <div className="p-6 space-y-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 mb-4">
              <FlaskConical className="h-4 w-4 text-muted" aria-hidden="true" />
              <span className="text-xs text-muted">
                Evaluation state is tenant-scoped. Exports exclude secrets and provider payloads.
              </span>
            </div>
            <EvaluationLabConsole />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
