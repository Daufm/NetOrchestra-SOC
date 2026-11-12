/** SOC dark theme tokens from the project specification. */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#070b11",
          card: "#0b131f",
          neon: "#00ff66",
          deep: "#043e26",
          border: "#162235",
          text: "#cbd5e1",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: { neon: "0 0 12px rgba(0, 255, 102, 0.25)" },
    },
  },
  plugins: [],
};
