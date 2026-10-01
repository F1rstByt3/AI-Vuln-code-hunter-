/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0e14",
        panel: "#11151f",
        panel2: "#151b27",
        border: "#1e2633",
        muted: "#8b97a7",
        accent: "#6366f1",        // indigo — brand highlight (tabs, primary actions)
        "accent-hover": "#818cf8",
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.3), 0 1px 1px rgba(0,0,0,0.2)",
        glow: "0 0 0 1px rgba(99,102,241,0.4)",
      },
    },
  },
  plugins: [],
};
