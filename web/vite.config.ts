/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Compile-time constant so the demo code path (and its 1.4 MB fixture) is
  // dead-code-eliminated from the normal build. `build:demo` sets VITE_DEMO=1.
  define: {
    __DEMO__: JSON.stringify(process.env.VITE_DEMO === "1"),
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:4000",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
