/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        shodh: {
          bg: "#0a0a0f",
          surface: "#12121a",
          border: "#1e1e2e",
          text: "#e2e2e8",
          muted: "#6b6b80",
          accent: "#00ff88",
          "accent-dim": "#00cc6a",
          danger: "#ff3355",
          warning: "#ffaa00",
          info: "#00aaff",
          purple: "#8855ff",
        },
      },
      fontFamily: {
        // Data, IPs, ports, CVE IDs, code — retro-futuristic terminal feel
        mono: ['"Space Mono"', "monospace"],
        // UI labels, body text, nav, badges — angular and technical
        sans: ["Rajdhani", "system-ui", "sans-serif"],
        // Big titles only (logo, hero H1, section H2) — definitive cyberpunk
        display: ["Orbitron", "sans-serif"],
      },
      animation: {
        "pulse-glow": "pulse-glow 2s ease-in-out infinite",
        "scan-line": "scan-line 3s linear infinite",
        "fade-in": "fade-in 0.5s ease-out",
        "slide-up": "slide-up 0.5s ease-out",
      },
      keyframes: {
        "pulse-glow": {
          "0%, 100%": { opacity: "1", filter: "brightness(1)" },
          "50%": { opacity: "0.8", filter: "brightness(1.3)" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "slide-up": {
          "0%": { opacity: "0", transform: "translateY(20px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
