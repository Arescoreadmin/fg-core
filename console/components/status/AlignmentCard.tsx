import type { AlignmentArtifact } from '@/lib/coreApi';

export function AlignmentCard({ artifact, commit }: { artifact: AlignmentArtifact | null; commit: string }) {
  if (!artifact) {
    return (
      <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '1rem' }}>
        <h3>No artifact published yet</h3>
        <p>Enable CI publish for alignment artifacts, then point NEXT_PUBLIC_ALIGNMENT_ARTIFACT_URL to the JSON file.</p>
        <p>Last-known commit: <code>{commit}</code></p>
      </div>
    );
  }

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '1rem' }}>
      <h3>Alignment Status: {artifact.pass ? 'PASS' : 'FAIL'}</h3>
      <p>Drift: {artifact.drift_status || 'unknown'}</p>
      <p>Counts: {artifact.drift_count ?? 0} drifted / {artifact.checked_count ?? 0} checked</p>
      <p>Generated: {artifact.generated_at || 'unknown'}</p>
      <p>Commit: <code>{artifact.commit || commit}</code></p>
    </div>
  );
}
