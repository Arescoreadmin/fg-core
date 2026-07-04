'use client';

import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-BENCHMARKS';
const AUTHORITY = 'Trust Benchmarks Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

export interface TrustBenchmark {
  id: string;
  name: string;
  description: string;
  ourScore: number;
  benchmarkScore: number;
  dataSource: string;
  asOf: string;
  delta: number;
}

interface TrustBenchmarksProps {
  benchmarks: TrustBenchmark[];
  loading?: boolean;
  lastUpdated?: string;
}

function DeltaCell({ delta }: { delta: number }) {
  if (delta > 0) return <span className="text-success">+{delta}</span>;
  if (delta < 0) return <span className="text-danger">{delta}</span>;
  return <span className="text-muted">0</span>;
}

export default function TrustBenchmarks({ benchmarks, loading, lastUpdated }: TrustBenchmarksProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Authoritative trust benchmark comparison"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Trust Benchmarks"
    >
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : benchmarks.length === 0 ? (
        <div className="rounded-md border border-border bg-muted/20 px-3 py-3 text-xs text-muted">
          No benchmark data available. Benchmarks are shown only when authoritative comparison data exists.
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted text-left">
                  <th className="pb-2 pr-3 font-medium">Benchmark Name</th>
                  <th className="pb-2 pr-3 font-medium">Description</th>
                  <th className="pb-2 pr-3 font-medium">Our Score</th>
                  <th className="pb-2 pr-3 font-medium">Benchmark Score</th>
                  <th className="pb-2 pr-3 font-medium">Delta</th>
                  <th className="pb-2 pr-3 font-medium">Data Source</th>
                  <th className="pb-2 font-medium">As Of</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {benchmarks.map((b) => (
                  <tr key={b.id} className="text-foreground">
                    <td className="py-2 pr-3 font-medium">{b.name}</td>
                    <td className="py-2 pr-3 text-muted">{b.description}</td>
                    <td className="py-2 pr-3">{b.ourScore}</td>
                    <td className="py-2 pr-3">{b.benchmarkScore}</td>
                    <td className="py-2 pr-3"><DeltaCell delta={b.delta} /></td>
                    <td className="py-2 pr-3">{b.dataSource}</td>
                    <td className="py-2">{new Date(b.asOf).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[10px] text-muted">
            Benchmark data sourced from authoritative external references only.
          </p>
        </>
      )}
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
