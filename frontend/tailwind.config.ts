import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        surface: {
          lowest: "#060910",
          low: "#0f1523",
          DEFAULT: "#151c2e",
          high: "#1d263b",
          highest: "#28344f",
        },
        primary: {
          DEFAULT: "#06b6d4",
          focus: "#22d3ee",
          dim: "#0891b2",
        },
        secondary: {
          DEFAULT: "#f59e0b",
          dim: "#d97706",
        },
        threat: {
          DEFAULT: "#f43f5e",
          dim: "#be123c",
        },
      },
      fontFamily: {
        mono: ["var(--font-jetbrains)", "JetBrains Mono", "monospace"],
        sans: ["var(--font-hanken)", "Hanken Grotesk", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;