import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  envDir: "..", // read the repo-root .env (VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY)
  server: { port: 5173, proxy: { "/api": "http://localhost:4000", "/ingest": "http://localhost:4000" } },
});
