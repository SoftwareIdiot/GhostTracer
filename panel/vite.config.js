import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base: "./" is required — the panel is loaded as a local extension page
// (chrome-extension://.../panel/dist/index.html), not from a server root.
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    port: 5173,
    strictPort: true,
    fs: { allow: [".."] }
  },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    emptyOutDir: true,
    target: "es2020",
    modulePreload: false, // avoid Vite's inline bootstrap script, which the extension CSP (script-src 'self', no 'unsafe-inline') would block
    rollupOptions: { input: ["index.html", "dashboard.html"] }
  }
});
