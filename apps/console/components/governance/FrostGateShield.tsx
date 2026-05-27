'use client';

import { useId } from 'react';

export function FrostGateShield({
  className,
  size = 24,
}: {
  className?: string;
  size?: number;
}) {
  // Unique IDs prevent clip-path conflicts when multiple shields appear on the
  // same page (nav + footer + hero all rendered in one HTML document).
  const uid = useId().replace(/:/g, '');
  const leftId = `fg-shield-left-${uid}`;
  const rightId = `fg-shield-right-${uid}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="FrostGate — Trust But Verify"
    >
      <title>FrostGate — Trust But Verify</title>
      <defs>
        {/* Left half: Trust (blue) */}
        <clipPath id={leftId}>
          <polygon points="12,0 12,24 0,24 0,0" />
        </clipPath>
        {/* Right half: Verify (orange) */}
        <clipPath id={rightId}>
          <polygon points="12,0 24,0 24,24 12,24" />
        </clipPath>
      </defs>

      {/* Trust half — blue */}
      <path
        d="M12 2L4 5.5V11C4 15.5 7.5 19.7 12 21C16.5 19.7 20 15.5 20 11V5.5L12 2Z"
        fill="#3B82F6"
        clipPath={`url(#${leftId})`}
      />
      {/* Verify half — orange */}
      <path
        d="M12 2L4 5.5V11C4 15.5 7.5 19.7 12 21C16.5 19.7 20 15.5 20 11V5.5L12 2Z"
        fill="#FF5A1F"
        clipPath={`url(#${rightId})`}
      />
      {/* Centre divider */}
      <line
        x1="12"
        y1="2"
        x2="12"
        y2="21"
        stroke="rgba(255,255,255,0.25)"
        strokeWidth="0.5"
      />
    </svg>
  );
}
