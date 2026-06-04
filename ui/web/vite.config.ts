import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// SPA served at the root by the BFF; /api is the BFF, /dev proxy for local dev.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8088",
    },
  },
});
