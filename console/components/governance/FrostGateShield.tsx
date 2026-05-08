export function FrostGateShield({ className, size = 24 }: { className?: string; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="FrostGate"
    >
      <defs>
        <clipPath id="shield-left">
          <polygon points="12,0 12,24 0,24 0,0" />
        </clipPath>
        <clipPath id="shield-right">
          <polygon points="12,0 24,0 24,24 12,24" />
        </clipPath>
      </defs>
      {/* Shield path — left half: trust blue */}
      <path
        d="M12 2L4 5.5V11C4 15.5 7.5 19.7 12 21C16.5 19.7 20 15.5 20 11V5.5L12 2Z"
        fill="#3B82F6"
        clipPath="url(#shield-left)"
      />
      {/* Shield path — right half: risk orange */}
      <path
        d="M12 2L4 5.5V11C4 15.5 7.5 19.7 12 21C16.5 19.7 20 15.5 20 11V5.5L12 2Z"
        fill="#FF5A1F"
        clipPath="url(#shield-right)"
      />
      {/* Dividing line */}
      <line x1="12" y1="2" x2="12" y2="21" stroke="rgba(255,255,255,0.2)" strokeWidth="0.5" />
    </svg>
  );
}
