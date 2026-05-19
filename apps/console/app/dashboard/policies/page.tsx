import { ShieldCheck } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent } from '@/components/ui/card';

export default function PoliciesPage() {
  return (
    <div className="flex flex-col">
      <TopBar title="Policies" subtitle="OPA policy administration and enforcement status" />
      <div className="p-6">
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-10 text-center"
              aria-label="module-not-configured"
            >
              <ShieldCheck className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Policies module not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                This module will provide policy center workflows for OPA policy administration,
                enforcement rule management, and compliance policy visibility.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
