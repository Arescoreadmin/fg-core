import { AlignmentCard } from '@/components/status/AlignmentCard';
import { readAlignmentArtifact } from '@/lib/coreApi';

export default async function AlignmentPage() {
  const artifact = await readAlignmentArtifact();
  const commit = process.env.NEXT_PUBLIC_GIT_SHA || 'unknown';

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <h2>Alignment / Drift</h2>
      <AlignmentCard artifact={artifact} commit={commit} />
    </div>
  );
}
