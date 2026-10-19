import { createClient } from "@supabase/supabase-js";

// Public values: the anon key is safe in the browser because the database tables are locked
// down (RLS, see supabase/schema.sql) and all data goes through the Sentinel API.
const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabaseConfigured = !!(url && anonKey);
export const supabase = createClient(url || "http://localhost:54321", anonKey || "missing-anon-key");
