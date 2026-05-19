import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
    '../../packages/ui/src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#05070A',
        foreground: '#E9EEF5',
        primary: {
          DEFAULT: '#FF5A1F',
          hover: '#CC4919',
          foreground: '#FFFFFF',
        },
        border: '#0B3A4A',
        muted: {
          DEFAULT: '#94A3B8',
          foreground: '#CBD5E1',
        },
        surface: {
          DEFAULT: '#0D1117',
          2: '#161B22',
          3: '#1C2333',
        },
        success: '#22C55E',
        warning: '#F59E0B',
        danger: '#EF4444',
        info: '#3B82F6',
        risk: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#22C55E',
        },
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '8px',
        sm: '4px',
        md: '8px',
        lg: '12px',
        xl: '16px',
        '2xl': '24px',
      },
    },
  },
  plugins: [],
};

export default config;
