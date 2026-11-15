import type { Config } from "tailwindcss";

/** Tokens definidos como canais RGB em globals.css (design system base TypeUI Enterprise — ver DESIGN.md). */
const token = (name: string): string => `rgb(var(--${name}) / <alpha-value>)`;

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: token("canvas"),
        band: token("band"),
        panel: token("panel"),
        raised: token("raised"),
        line: { DEFAULT: token("line"), strong: token("line-strong") },
        fg: { DEFAULT: token("fg"), muted: token("fg-muted"), faint: token("fg-faint") },
        accent: { DEFAULT: token("accent"), hover: token("accent-hover"), text: token("accent-text") },
        inverse: {
          DEFAULT: token("inverse"),
          raised: token("inverse-raised"),
          line: token("inverse-line"),
          fg: token("inverse-fg"),
          muted: token("inverse-muted"),
        },
        status: {
          critical: token("status-critical"),
          high: token("status-high"),
          medium: token("status-medium"),
          low: token("status-low"),
          info: token("status-info"),
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
        display: ["var(--font-display)", "Georgia", "serif"],
      },
      borderRadius: {
        DEFAULT: "4px",
        sm: "4px",
        md: "6px",
        lg: "8px",
      },
    },
  },
  plugins: [],
};

export default config;
