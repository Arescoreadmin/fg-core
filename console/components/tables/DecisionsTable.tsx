import type { DecisionOut } from '@/lib/coreApi';

export function DecisionsTable({
  decisions,
  onSelect,
}: {
  decisions: DecisionOut[];
  onSelect: (id: string) => void;
}) {
  if (!decisions.length) {
    return <div style={{ padding: '1rem', border: '1px dashed var(--border)' }}>No decisions for this tenant yet.</div>;
  }

  return (
    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
      <thead>
        <tr>
          <th style={{ textAlign: 'left' }}>ID</th>
          <th style={{ textAlign: 'left' }}>Event</th>
          <th style={{ textAlign: 'left' }}>Threat</th>
          <th style={{ textAlign: 'left' }}>Type</th>
          <th style={{ textAlign: 'left' }}>Created</th>
        </tr>
      </thead>
      <tbody>
        {decisions.map((d) => (
          <tr key={d.id} onClick={() => onSelect(d.id)} style={{ cursor: 'pointer', borderTop: '1px solid var(--border)' }}>
            <td>{d.id}</td>
            <td>{d.event_id}</td>
            <td>{d.threat_level}</td>
            <td>{d.event_type}</td>
            <td>{d.created_at || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
