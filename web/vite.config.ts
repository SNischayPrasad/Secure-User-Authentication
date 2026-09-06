import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/**
 * The dev server proxies /api to the Express server so the browser sees a single
 * origin. Cookies (refresh_token, csrf_token) then behave in development exactly
 * as they do in production behind a reverse proxy.
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
