import { ImageResponse } from 'next/og';

export const runtime = 'edge';
export const alt = 'FrostGate — Trust But Verify · AI Governance for Regulated Industries';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          background: '#05070A',
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
          position: 'relative',
          padding: '60px',
        }}
      >
        {/* Subtle grid background */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage:
              'linear-gradient(rgba(11,58,74,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(11,58,74,0.3) 1px, transparent 1px)',
            backgroundSize: '48px 48px',
          }}
        />

        {/* Shield mark — split rectangle representing Trust (blue) | Verify (orange) */}
        <div
          style={{
            display: 'flex',
            width: 80,
            height: 96,
            marginBottom: 36,
            position: 'relative',
          }}
        >
          {/* Trust half */}
          <div
            style={{
              flex: 1,
              background: '#3B82F6',
              borderRadius: '12px 0 0 40px',
            }}
          />
          {/* Verify half */}
          <div
            style={{
              flex: 1,
              background: '#FF5A1F',
              borderRadius: '0 12px 40px 0',
            }}
          />
          {/* Centre line */}
          <div
            style={{
              position: 'absolute',
              left: '50%',
              top: 0,
              bottom: 0,
              width: 1,
              background: 'rgba(255,255,255,0.15)',
            }}
          />
        </div>

        {/* Wordmark */}
        <div
          style={{
            color: '#E9EEF5',
            fontSize: 72,
            fontWeight: 700,
            letterSpacing: '-2px',
            lineHeight: 1,
            marginBottom: 12,
          }}
        >
          FrostGate
        </div>

        {/* Motto */}
        <div
          style={{
            color: '#FF5A1F',
            fontSize: 18,
            fontWeight: 600,
            letterSpacing: '6px',
            textTransform: 'uppercase',
            marginBottom: 24,
          }}
        >
          Trust But Verify
        </div>

        {/* Tagline */}
        <div
          style={{
            color: '#94A3B8',
            fontSize: 26,
            textAlign: 'center',
            maxWidth: 680,
            lineHeight: 1.4,
            marginBottom: 48,
          }}
        >
          AI Governance for Regulated Industries
        </div>

        {/* Framework strip */}
        <div
          style={{
            display: 'flex',
            gap: 20,
            color: '#475569',
            fontSize: 13,
            fontWeight: 500,
          }}
        >
          {['NIST AI RMF', '·', 'HIPAA', '·', 'FFIEC CAT', '·', 'CMMC 2.0', '·', 'SOC 2'].map(
            (item, i) => (
              <span key={i}>{item}</span>
            )
          )}
        </div>

        {/* Domain tag bottom-right */}
        <div
          style={{
            position: 'absolute',
            bottom: 32,
            right: 48,
            color: '#334155',
            fontSize: 15,
            fontWeight: 500,
            letterSpacing: '0.5px',
          }}
        >
          frostgate.ai
        </div>
      </div>
    ),
    { ...size }
  );
}
