
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    allowedHosts: [
      "localhost",
      "127.0.0.1",
      "shingle-attire-define.ngrok-free.dev",
    ],
    proxy: {
      "/api": {
        target: process.env.VITE_BACKEND_URL || "http://localhost:8080",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  test: { environment: "node" },
});
