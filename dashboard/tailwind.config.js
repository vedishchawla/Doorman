/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        serif: ['"Instrument Serif"', 'Georgia', 'serif'],
        sans: ['"Plus Jakarta Sans"', '-apple-system', 'BlinkMacSystemFont', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        bone: {
          DEFAULT: '#F4F3EE',
          elevated: '#EAE8E0',
        },
        hairline: '#D5D2C8',
        carbon: {
          DEFAULT: '#0E0F10',
          elevated: '#161719',
          hairline: '#26282B',
        },
        ink: {
          DEFAULT: '#141413',
          muted: '#5E5D59',
        },
        vermilion: {
          DEFAULT: '#E63B2E',
          dim: '#3B1614',
        },
        emerald: {
          DEFAULT: '#1B7F5C',
          bright: '#2AC78A',
          dim: '#122E24',
        },
        amber: {
          DEFAULT: '#D97706',
          dim: '#33220D',
        },
      },
      borderRadius: {
        none: '0px',
        sm: '2px',
        DEFAULT: '2px',
        md: '2px',
        lg: '2px',
      },
      transitionTimingFunction: {
        expo: 'cubic-bezier(0.19, 1, 0.22, 1)',
        arch: 'cubic-bezier(0.76, 0, 0.24, 1)',
      },
    },
  },
  plugins: [],
};
