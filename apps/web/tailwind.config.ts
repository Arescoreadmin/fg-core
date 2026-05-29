import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        frost: {
          50: '#f0f7ff',
          100: '#e0efff',
          200: '#baddff',
          300: '#7dc0ff',
          400: '#38a0fa',
          500: '#0e80eb',
          600: '#0263c9',
          700: '#034fa3',
          800: '#074386',
          900: '#0c3870',
        },
      },
    },
  },
  plugins: [],
};

export default config;
