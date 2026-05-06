'use client';

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface DataPoint {
  time: string;
  allowed: number;
  blocked: number;
}

interface Props {
  data: DataPoint[];
}

export function RequestsChart({ data }: Props) {
  if (!data.length) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-muted">
        No request data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22C55E" stopOpacity={0.15} />
            <stop offset="95%" stopColor="#22C55E" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#EF4444" stopOpacity={0.15} />
            <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#0B3A4A" />
        <XAxis dataKey="time" tick={{ fill: '#94A3B8', fontSize: 10 }} />
        <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
        <Tooltip
          contentStyle={{
            backgroundColor: '#0D1117',
            border: '1px solid #0B3A4A',
            borderRadius: 8,
            fontSize: 12,
          }}
          labelStyle={{ color: '#E9EEF5' }}
        />
        <Area
          type="monotone"
          dataKey="allowed"
          stroke="#22C55E"
          strokeWidth={1.5}
          fill="url(#colorAllowed)"
          name="Allowed"
        />
        <Area
          type="monotone"
          dataKey="blocked"
          stroke="#EF4444"
          strokeWidth={1.5}
          fill="url(#colorBlocked)"
          name="Blocked"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
