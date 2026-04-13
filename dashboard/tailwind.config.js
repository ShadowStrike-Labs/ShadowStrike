/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        phantom: {
          50:  '#f0f4ff',
          100: '#e0e8ff',
          200: '#c7d4fe',
          300: '#a4b8fc',
          400: '#7b93f8',
          500: '#5a6ef2',
          600: '#4450e6',
          700: '#3740cb',
          800: '#2f36a4',
          900: '#2c3382',
          950: '#1a1e4c',
        },
        threat: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#eab308',
          low:      '#22c55e',
          info:     '#3b82f6',
        },
        surface: {
          DEFAULT: '#0f1117',
          raised:  '#161820',
          overlay: '#1e2029',
          subtle:  '#262833',
        },
        border: {
          DEFAULT: '#2e3142',
          subtle:  '#232538',
          focus:   '#5a6ef2',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in':    'fadeIn 0.3s ease-in-out',
        'slide-up':   'slideUp 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%':   { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};
