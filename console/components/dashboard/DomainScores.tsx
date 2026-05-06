'use client';

import {
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';

const DOMAIN_LABELS: Record<string, string> = {
  data_governance: 'Data Gov.',
  security_posture: 'Security',
  ai_maturity: 'AI Maturity',
  infra_readiness: 'Infra',
  compliance_awareness: 'Compliance',
  automation_potential: 'Automation',
};

interface Props {
  scores: Record<string, number>;
}

export function DomainScores({ scores }: Props) {
  const data = Object.entries(scores).map(([key, value]) => ({
    domain: DOMAIN_LABELS[key] ?? key,
    score: Math.round(value),
    fullMark: 100,
  }));

  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-muted">
        No domain scores available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <RadarChart cx="50%" cy="50%" outerRadius="70%" data={data}>
        <PolarGrid stroke="#0B3A4A" />
        <PolarAngleAxis
          dataKey="domain"
          tick={{ fill: '#94A3B8', fontSize: 11 }}
        />
        <Radar
          name="Score"
          dataKey="score"
          stroke="#FF5A1F"
          fill="#FF5A1F"
          fillOpacity={0.15}
          strokeWidth={2}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#0D1117',
            border: '1px solid #0B3A4A',
            borderRadius: 8,
            fontSize: 12,
          }}
          labelStyle={{ color: '#E9EEF5' }}
          formatter={(value: number) => [`${value}/100`, 'Score']}
        />
      </RadarChart>
    </ResponsiveContainer>
  );
}
