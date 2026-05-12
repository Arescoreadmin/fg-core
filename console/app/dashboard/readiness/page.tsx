import { Activity } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';

export default function ReadinessPage() {
  return (
    <div className="flex flex-col">
      <TopBar title="Readiness" subtitle="Compliance readiness assessment and gap analysis" />
      <div className="p-6">
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-10 text-center"
              aria-label="module-not-configured"
            >
              <Activity className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Readiness module not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                This module will provide readiness workflow dashboards showing compliance
                posture, gap analysis, and remediation progress against applicable frameworks.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
