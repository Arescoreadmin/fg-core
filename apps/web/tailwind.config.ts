import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans:    ['Inter', 'system-ui', 'sans-serif'],
        display: ['Oswald', 'Impact', 'system-ui', 'sans-serif'],
        mono:    ['JetBrains Mono', 'monospace'],
      },
      colors: {
        bg:    '#080808',
        surface: '#0f0f0f',
        border: '#1c1c1c',
        steel: {
          300: '#7aa5be',
          400: '#557fa0',
          500: '#3d6f95',
          600: '#2e5578',
          700: '#1e3b55',
          900: '#0a1b28',
        },
        rust: {
          400: '#b05040',
          500: '#8b3528',
          700: '#521512',
          900: '#1a0504',
        },
      },
    },
  },
  plugins: [],
};

export default config;
