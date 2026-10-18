import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The controller serves soc/dist at "/" and the JSON API at "/api" on the same
// origin, so the built app uses relative URLs. In dev, proxy to a local controller.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
  build: {
    chunkSizeWarningLimit: 2500,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes("three") || id.includes("globe")) return "globe";
          if (id.includes("echarts")) return "charts";
          if (id.includes("@xyflow")) return "flow";
        },
      },
    },
  },
});
