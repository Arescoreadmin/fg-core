import Link from 'next/link';
import { FileText, ArrowRight } from 'lucide-react';
import { ConsoleTopNav } from '@/components/ConsoleTopNav';

// Assessment Reports landing — no report selected.
// Report detail is available at /reports/[reportId].
// Navigate via Field Assessments to open a specific report.

export default function ReportsPage() {
  return (
    <div className="min-h-screen bg-background">
      <ConsoleTopNav
        crumbs={[{ label: 'Assessment Reports' }]}
      />

      <main className="max-w-2xl mx-auto px-4 py-16">
        <div
          className="flex flex-col items-center gap-5 rounded-lg border border-border bg-surface-2 px-8 py-14 text-center"
          data-mcim-id="MCIM-18.6-REPORTS"
          data-workspace="reports"
          data-authority="Report Authority"
          data-testid="reports-landing"
          role="status"
          aria-label="Assessment Reports landing"
        >
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-muted/40">
            <FileText className="h-7 w-7 text-muted" aria-hidden="true" />
          </div>

          <div className="space-y-2">
            <h1 className="text-base font-semibold text-foreground">
              Assessment Reports
            </h1>
            <p className="text-sm text-muted">
              Reports are generated from completed field assessments.
            </p>
            <p className="text-xs text-muted">
              Open a field assessment engagement to access or generate a report.
            </p>
          </div>

          <Link
            href="/field-assessment"
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary/90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
          >
            Open Field Assessments
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>
      </main>
    </div>
  );
}
