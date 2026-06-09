/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0e14",
        panel: "#11151f",
        border: "#1e2633",
        muted: "#8b97a7",
      },
    },
  },
  plugins: [],
};
