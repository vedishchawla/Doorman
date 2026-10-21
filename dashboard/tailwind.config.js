/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    // Lock spacing strictly to 4, 8, 12, 16, 24, 32, 48 px scale (+ 0)
    spacing: {
      '0': '0px',
      '1': '4px',
      '2': '8px',
      '3': '12px',
      '4': '16px',
      '6': '24px',
      '8': '32px',
      '12': '48px',
    },
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', '-apple-system', 'BlinkMacSystemFont', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        accent: {
          DEFAULT: '#0f62fe',
          hover: '#0043ce',
          active: '#002d9c',
          subtle: '#edf5ff',
          'subtle-dark': '#001d6c',
        },
        // Strict neutral greys meeting WCAG AA contrast (>= 4.5:1)
        neutral: {
          50: '#f8f9fa',
          100: '#f4f4f4',
          200: '#e0e0e0',
          300: '#c6c6c6',
          400: '#8d8d8d',
          500: '#6f6f6f',
          600: '#525252',
          700: '#393939',
          800: '#262626',
          900: '#161616',
          950: '#121212',
        },
        status: {
          allow: '#198038',
          'allow-dark': '#42be65',
          deny: '#da1e28',
          'deny-dark': '#fa4d56',
          warn: '#b28600',
          'warn-dark': '#f1c21b',
        }
      },
      borderRadius: {
        none: '0px',
        sm: '2px',
        DEFAULT: '2px',
        md: '2px',
        lg: '2px',
      },
      boxShadow: {
        none: 'none',
      }
    },
  },
  plugins: [],
}
