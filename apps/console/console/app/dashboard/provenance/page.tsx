import { ShieldCheck } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { ProvenanceValidationPanel } from '@/components/governance';

export default function ProvenancePage() {
  return (
    <div className="flex flex-col" aria-label="provenance-page">
      <TopBar title="Provenance" subtitle="Source attribution and citation validation" />
      <div className="space-y-4 p-6">

        {/* Page header */}
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />
          <div>
            <h1 className="text-sm font-semibold text-foreground">
              Provenance Validation
            </h1>
            <p className="text-xs text-muted">
              Operator-readable proof that answer citations are valid, rejected, or unavailable.
            </p>
          </div>
        </div>

        {/* Provenance validation panel */}
        <Card aria-label="provenance-validation-card">
          <CardHeader className="pb-2">
            <h2 className="text-xs font-semibold text-foreground">
              Citation Validation Status
            </h2>
            <p className="text-[10px] text-muted">
              Use the AI Workspace to generate a response. Per-response provenance validation
              results appear in that view. This route provides a dedicated provenance explorer.
            </p>
          </CardHeader>
          <CardContent>
            <ProvenanceValidationPanel provenance={null} />
          </CardContent>
        </Card>

        {/* Module status — preserved for shell contract */}
        <Card>
          <CardContent className="pt-6">
            <div
              className="flex flex-col items-center gap-3 py-6 text-center"
              aria-label="module-not-configured"
            >
              <ShieldCheck className="h-8 w-8 text-muted/40" aria-hidden="true" />
              <p className="text-sm font-medium text-foreground">
                Provenance explorer not yet configured
              </p>
              <p className="max-w-sm text-xs text-muted">
                Full provenance history and per-session citation audit explorer workflows
                are not yet configured for this deployment. The validation panel above
                reflects real-time results from AI Workspace queries.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Capability overview */}
        <Card aria-label="provenance-capability-overview">
          <CardContent className="pt-4">
            <h2 className="mb-3 text-xs font-semibold text-foreground">
              Provenance Validation Capabilities
            </h2>
            <ul
              className="space-y-2 text-xs text-muted"
              aria-label="provenance-capability-list"
            >
              {[
                'Citation validation state: valid, invalid, rejected, unavailable, no-context',
                'Per-citation rejection reason with machine-readable reason code',
                'Retrieved vs prompt-included vs cited chunk distinction',
                'Provenance trust status derived from validation result',
                'Export-safe summary: no raw vectors, no prompts, no secrets',
                'Conservative legal/compliance wording — no implied approval',
              ].map(item => (
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
