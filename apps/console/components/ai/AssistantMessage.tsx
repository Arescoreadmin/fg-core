import { cn } from '@/lib/cn';
import {
  PolicyDecision,
  ProviderRouteCard,
  ConfidenceMeter,
  CitationViewer,
  RetrievalTrace,
  HumanReviewPanel,
} from '@/components/governance';
import type { Citation, TraceStep } from '@/components/governance';

export interface MessageMeta {
  provider?: string;
  model?: string;
  latencyMs?: number;
  policyDecision?: { action: string; reason?: string; policy?: string };
  confidence?: number;
  citations?: Citation[];
  retrievalSteps?: TraceStep[];
  correlationId?: string;
  sessionId?: string;
}

interface Props {
  role: 'user' | 'assistant';
  content: string;
  meta?: MessageMeta;
  onApprove?: () => void;
  onReject?: () => void;
}

export function AssistantMessage({ role, content, meta, onApprove, onReject }: Props) {
  const isUser = role === 'user';
  const needsReview = meta?.policyDecision?.action?.toLowerCase() === 'review';

  return (
    <div className={cn('flex', isUser ? 'justify-end' : 'justify-start')}>
      <div className={cn('max-w-[75%] space-y-2', isUser ? 'items-end' : 'items-start')}>
        {/* Message bubble */}
        <div
          className={cn(
            'rounded-xl px-4 py-3 text-sm leading-relaxed',
            isUser
              ? 'bg-primary text-white rounded-br-sm'
              : 'bg-surface-2 border border-border text-foreground rounded-bl-sm',
          )}
        >
          {content}
        </div>

        {/* Human review required */}
        {!isUser && needsReview && meta && (
          <HumanReviewPanel
            requestId={meta.correlationId ?? '—'}
            summary="This response requires human review before acting on it."
            policy={meta.policyDecision?.policy}
            onApprove={onApprove}
            onReject={onReject}
          />
        )}

        {/* Governance footer — assistant only */}
        {!isUser && meta && (
          <div className="space-y-2 w-full">
            {/* Provider + policy */}
            <div className="flex flex-wrap gap-2 items-start">
              {meta.provider && (
                <ProviderRouteCard
                  provider={meta.provider}
                  model={meta.model}
                  latencyMs={meta.latencyMs}
                  decision={meta.policyDecision?.action}
                  className="flex-1 min-w-[200px]"
                />
              )}
              {meta.policyDecision && !meta.provider && (
                <PolicyDecision
                  action={meta.policyDecision.action}
                  reason={meta.policyDecision.reason}
                  policy={meta.policyDecision.policy}
                />
              )}
            </div>

            {/* Confidence */}
            {meta.confidence !== undefined && (
              <ConfidenceMeter value={meta.confidence} />
            )}

            {/* Citations */}
            {meta.citations && meta.citations.length > 0 && (
              <CitationViewer citations={meta.citations} />
            )}

            {/* Retrieval trace */}
            {meta.retrievalSteps && meta.retrievalSteps.length > 0 && (
              <RetrievalTrace steps={meta.retrievalSteps} />
            )}

            {/* Correlation ID */}
            {meta.correlationId && (
              <p className="font-mono text-[10px] text-muted/40">
                corr: {meta.correlationId}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
