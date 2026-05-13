import { ShieldCheck } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { RetrievalPolicyCenterContainer } from '@/components/governance';

export default function RetrievalPage() {
  return (
    <div className="flex flex-col" aria-label="retrieval-page">
      <TopBar title="Retrieval" subtitle="Retrieval governance policy and corpus access controls" />
      <div className="space-y-4 p-6">

        {/* Page header */}
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />
          <div>
            <h1 className="text-sm font-semibold text-foreground">
              Retrieval Policy Center
            </h1>
            <p className="text-xs text-muted">
              Operator-controlled retrieval governance. Manage corpus access, strategy,
              grounded-answer enforcement, and fallback behavior.
            </p>
          </div>
        </div>

        {/* Retrieval Policy Center — wired to live backend */}
        <Card aria-label="retrieval-policy-center-card">
          <CardHeader className="pb-2">
            <h2 className="text-xs font-semibold text-foreground">
              Retrieval Governance Policy
            </h2>
            <p className="text-[10px] text-muted">
              Policy state reflects actual backend enforcement. Changes require explicit save.
              Invalid configurations are rejected before save. All changes are audit-logged.
            </p>
          </CardHeader>
          <CardContent>
            <RetrievalPolicyCenterContainer />
          </CardContent>
        </Card>

        {/* Capability overview */}
        <Card aria-label="retrieval-policy-capabilities">
          <CardContent className="pt-4">
            <h2 className="mb-3 text-xs font-semibold text-foreground">
              Retrieval Policy Center Capabilities
            </h2>
            <ul
              className="space-y-2 text-xs text-muted"
              aria-label="retrieval-policy-capability-list"
            >
              {[
                'Corpus access control: allowed, denied, inherited states — denied overrides allowed',
                'Retrieval strategy selection: lexical, semantic, hybrid, hybrid_rrf (validated before save)',
                'Top-K control: validated integer bounds (1–20), no silent coercion',
                'Semantic enable/disable: cannot bypass denied corpora or tenant isolation',
                'Grounded-answer enforcement: active state matches backend verifier behavior',
                'Lexical fallback: never bypasses denied corpora or tenant isolation',
                'Policy preview: explains effective state without executing live retrieval',
                'Validation before save: client-side and backend-side — invalid configs fail closed',
                'Audit summary: change log with timestamps, actors, and changed fields',
                'No raw vectors, no provider internals, no secrets exposed',
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
