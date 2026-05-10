import { AlignmentCard } from '@/components/status/AlignmentCard';
import { readAlignmentArtifact } from '@/lib/coreApi';
import { TopBar } from '@/components/layout/TopBar';

export default async function AlignmentPage() {
  const artifact = await readAlignmentArtifact();
  const commit = process.env.NEXT_PUBLIC_GIT_SHA || 'unknown';

  return (
    <div className="flex flex-col">
      <TopBar
        title="Alignment"
        subtitle="Compliance drift monitoring across governance frameworks"
      />
      <div className="p-6 space-y-4">
        <AlignmentCard artifact={artifact} commit={commit} />
      </div>
    </div>
  );
}
