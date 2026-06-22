import type { AlignmentArtifact } from '@/lib/coreApi';

export function AlignmentCard({ artifact, commit }: { artifact: AlignmentArtifact | null; commit: string }) {
  if (!artifact) {
    return (
      <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '1rem' }}>
        <h3>No artifact published yet</h3>
        <p>Set ALIGNMENT_ARTIFACT_URL to a JSON artifact endpoint.</p>
        <p>Last-known commit: <code>{commit}</code></p>
      </div>
    );
  }

  const rawScore = artifact['score'];
  const score = typeof rawScore === 'number' ? rawScore : artifact.pass ? 1 : 0;

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '1rem' }}>
      <h3>Alignment Status: {artifact.pass ? 'PASS' : 'FAIL'}</h3>
      <p>Score: {score}</p>
      <p>Policy hash: <code>{String(artifact.policy_hash || 'unknown')}</code></p>
      <p>Artifact id: <code>{String(artifact.artifact_id || 'unknown')}</code></p>
      <p>Generated: {artifact.generated_at || 'unknown'}</p>
      <p>Commit: <code>{String(artifact.commit || commit)}</code></p>
      <details>
        <summary>Raw JSON</summary>
        <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(artifact, null, 2)}</pre>
      </details>
    </div>
  );
}
