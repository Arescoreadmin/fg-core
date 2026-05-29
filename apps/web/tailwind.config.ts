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
        // Extracted from brand shield — left half steel blue, right half rust red
        steel: {
          50:  '#eef3f7',
          100: '#d5e2ec',
          200: '#a9c4d8',
          300: '#7aa5c2',
          400: '#5589ae',
          500: '#3d6f95',
          600: '#2e5878',
          700: '#234460',
          800: '#1a3349',
          900: '#122435',
        },
        rust: {
          50:  '#faf0ee',
          100: '#f2d8d3',
          200: '#e4ada4',
          300: '#d27e72',
          400: '#be5547',
          500: '#9b3830',
          600: '#7d2c25',
          700: '#61221c',
          800: '#471a15',
          900: '#31120e',
        },
      },
    },
  },
  plugins: [],
};

export default config;
