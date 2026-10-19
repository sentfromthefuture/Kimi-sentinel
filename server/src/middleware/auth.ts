import type { Request, Response, NextFunction } from "express";
import crypto from "node:crypto";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { config } from "../config.js";

export interface AuthedRequest extends Request { userId?: string; userEmail?: string; }

let client: SupabaseClient | null = null;
function supabase(): SupabaseClient {
  client ??= createClient(config.supabase.url, config.supabase.anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return client;
}

// Tokens Supabase has just validated are cached briefly, so the dashboard's polling
// doesn't hit the Auth server on every request.
const CACHE_TTL_MS = 30_000;
const cache = new Map<string, { userId: string; email?: string; until: number }>();

// The browser signs in with Supabase Auth and sends its access token as "Authorization: Bearer <jwt>".
export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!config.supabase.url || !config.supabase.anonKey)
    return res.status(500).json({ error: "Server is missing SUPABASE_URL / SUPABASE_ANON_KEY" });
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  const key = crypto.createHash("sha256").update(token).digest("hex");
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) {
    req.userId = hit.userId; req.userEmail = hit.email;
    return next();
  }
  try {
    const { data, error } = await supabase().auth.getUser(token);
    if (error || !data.user) {
      cache.delete(key);
      // 4xx = token rejected; anything else = Supabase unreachable (don't sign the user out for that).
      const rejected = !error || (error.status !== undefined && error.status >= 400 && error.status < 500);
      return res.status(rejected ? 401 : 503).json({ error: rejected ? "Session expired" : "Auth service unavailable" });
    }
    if (cache.size > 1000) cache.clear();
    cache.set(key, { userId: data.user.id, email: data.user.email, until: Date.now() + CACHE_TTL_MS });
    req.userId = data.user.id; req.userEmail = data.user.email;
    next();
  } catch (err) {
    console.error("auth check failed", err);
    res.status(503).json({ error: "Auth service unavailable" });
  }
}
