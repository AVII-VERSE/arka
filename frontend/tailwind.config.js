/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#090D16',
          800: '#0F172A',
          700: '#1E293B',
          600: '#334155',
        },
        cyber: {
          blue: '#00F0FF',
          red: '#FF2A6D',
          green: '#05FFA1',
          yellow: '#FFE600',
          purple: '#7000FF',
        },
      },
    },
  },
  plugins: [],
};
