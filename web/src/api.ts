import { supabase } from "./supabase";

export async function api(path: string, opts: RequestInit = {}) {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  const res = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json", "x-requested-with": "sentinel",
      ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(opts.headers ?? {}),
    },
  });
  if (res.status === 401) { await supabase.auth.signOut(); } // App swaps back to the login screen
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body as any).error ?? `HTTP ${res.status}`);
  return body;
}

export const SEV = ["info", "low", "medium", "high", "critical"];
export const sevColor = (s: number) =>
  ["text-gray-400", "text-blue-400", "text-yellow-400", "text-orange-400", "text-red-500"][s] ?? "text-gray-400";
