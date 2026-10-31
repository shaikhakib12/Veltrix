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
        veltrix: {
          bg: '#0A0F1D',
          surface: '#0D1527',
          card: '#111C35',
          border: '#1E293B',
          cyan: '#00F2FE',
          cyanMuted: '#00C2CB',
          blue: '#3B82F6',
          textMuted: '#94A3B8',
          textBright: '#F8FAFC',
          danger: '#EF4444',
          warning: '#F59E0B',
          success: '#10B981',
        },
      },
    },
  },
  plugins: [],
}
