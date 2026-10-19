import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Load the repo-root .env (the same file the web app reads). Variables already set win.
try { process.loadEnvFile(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../.env")); } catch { /* no .env file */ }

const env = (k: string, d = "") => process.env[k] ?? d;

function deriveKey(): Buffer {
  const raw = env("CREDENTIAL_KEY");
  if (raw) return Buffer.from(raw, "base64");
  // Dev-only fallback: derive a stable key from APP_SECRET so the app runs without setup.
  // Set CREDENTIAL_KEY explicitly in production.
  return crypto.createHash("sha256").update(env("APP_SECRET", "sentinel-dev-secret")).digest();
}

export const config = {
  port: Number(env("PORT", "4000")),
  databaseUrl: env("DATABASE_URL"),
  // Supabase Auth: the server validates the browser's access token. Anon key is public by design.
  supabase: { url: env("SUPABASE_URL"), anonKey: env("SUPABASE_ANON_KEY") },
  appSecret: env("APP_SECRET", "sentinel-dev-secret"),
  webOrigin: env("WEB_ORIGIN", "http://localhost:5173"),
  credentialKey: deriveKey(),
  ai: {
    provider: env("AI_PROVIDER", "heuristic"),
    apiKey: env("OPENAI_API_KEY"),
    model: env("OPENAI_MODEL", "gpt-4o-mini"),
    baseUrl: env("OPENAI_BASE_URL", "https://api.openai.com/v1"),
  },
  // Deterministic policy defaults. Not modifiable by the agent.
  policy: {
    maxAutoActionDurationMin: 60,
    minConfidenceAuto: 0.85,
    minSeverityAuto: 3,
    allowlistedIps: ["127.0.0.1", "::1"],
    actionRateLimitPerHour: 20,
  },
};
