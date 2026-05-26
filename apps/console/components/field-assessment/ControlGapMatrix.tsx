'use client';

// Renders the framework_summary section from a GovernanceReport.
// framework_summary maps framework names to covered control IDs.
// Known frameworks with no coverage are shown as gap rows.

const KNOWN_FRAMEWORKS = ['NIST-AI-RMF', 'HIPAA', 'CMMC', 'SOC2'];

type CellState = 'covered' | 'gap' | 'partial' | 'unknown';

const CELL_LABEL: Record<CellState, string> = {
  covered: 'Covered',
  gap: 'Gap',
  partial: 'Partial',
  unknown: 'Unknown',
};

const CELL_COLOR: Record<CellState, string> = {
  covered: 'text-success border-success/30 bg-success/5',
  gap: 'text-danger border-danger/30 bg-danger/5',
  partial: 'text-warning border-warning/30 bg-warning/5',
  unknown: 'text-muted border-border bg-surface-2',
};

function CellBadge({ state }: { state: CellState }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${CELL_COLOR[state]}`}
      aria-label={CELL_LABEL[state]}
    >
      {CELL_LABEL[state]}
    </span>
  );
}

interface Props {
  data: Record<string, string[]> | null | undefined;
}

export function ControlGapMatrix({ data }: Props) {
  // Render known frameworks as "gap" rows even when data is empty — only skip if no data at all.
  if (data == null) return null;

  // Build the union of frameworks: known ones + any extras from backend
  const backendFrameworks = Object.keys(data);
  const allFrameworks = [
    ...KNOWN_FRAMEWORKS,
    ...backendFrameworks.filter((f) => !KNOWN_FRAMEWORKS.includes(f)),
  ];

  return (
    <div className="space-y-2" aria-label="control-gap-matrix">
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">Control Gap Matrix</p>
      <div className="overflow-x-auto">
        <table className="w-full text-xs border-collapse" role="table" aria-label="Framework control coverage">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left py-2 px-3 text-muted font-semibold w-40" scope="col">Framework</th>
              <th className="text-left py-2 px-3 text-muted font-semibold" scope="col">Coverage</th>
              <th className="text-left py-2 px-3 text-muted font-semibold w-20" scope="col">Status</th>
              <th className="text-left py-2 px-3 text-muted font-semibold w-20" scope="col">Controls</th>
            </tr>
          </thead>
          <tbody>
            {allFrameworks.map((fw) => {
              const controls = data[fw] ?? [];
              const state: CellState = controls.length === 0 ? 'gap' : 'covered';
              return (
                <tr key={fw} className="border-b border-border hover:bg-surface-2 transition-colors">
                  <td className="py-2 px-3 font-medium text-foreground" scope="row">{fw}</td>
                  <td className="py-2 px-3">
                    {controls.length > 0 ? (
                      <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
                        {controls.map((c, i) => (
                          <span
                            key={i}
                            className="font-mono inline-flex items-center rounded px-1.5 py-0.5 border border-info/20 bg-info/5 text-info"
                            aria-label={`Control ${c} covered`}
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-muted">No controls mapped</span>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <CellBadge state={state} />
                  </td>
                  <td className="py-2 px-3 font-mono text-muted">{controls.length}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
