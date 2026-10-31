/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#060911',
          900: '#0B0F19',
          850: '#0F1523',
          800: '#141C2E',
          700: '#1F293D',
        },
        cyan: {
          400: '#22D3EE',
          500: '#06B6D4',
          accent: '#00F5FF',
        },
        cyber: {
          dark: '#0B0F19',
          card: '#0F1523',
          cardHover: '#151C2E',
          border: '#1E293B',
          borderActive: '#00F5FF',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'glow-cyan': '0 0 15px -3px rgba(0, 245, 255, 0.25)',
        'glow-rose': '0 0 15px -3px rgba(244, 63, 94, 0.25)',
        'glow-amber': '0 0 15px -3px rgba(245, 158, 11, 0.25)',
      }
    },
  },
  plugins: [],
}
