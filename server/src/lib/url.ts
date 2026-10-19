import dns from "node:dns/promises";
import net from "node:net";

export interface ParsedTarget { url: string; hostname: string; protocol: "http:" | "https:"; }

const BLOCKED_HOSTNAMES = new Set([
  "localhost", "ip6-localhost", "ip6-loopback", "broadcasthost",
]);

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    return s === "::1" || s === "::" || s.startsWith("fc") || s.startsWith("fd") || s.startsWith("fe80");
  }
  if (!net.isIPv4(ip)) return true;
  const p = ip.split(".").map(Number);
  return (
    p[0] === 10 || p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) ||          // link-local / cloud metadata range
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127) // CGNAT
  );
}

// Validates and normalizes a user-submitted URL. Rejects unsafe destinations BEFORE any network I/O.
export async function validateTargetUrl(raw: string): Promise<ParsedTarget> {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new Error("Invalid URL");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("Unsupported protocol (http/https only)");
  if (u.username || u.password) throw new Error("Credentials in URL are not allowed");
  const hostname = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname.includes(".") && hostname !== "localhost") throw new Error("Invalid hostname");
  if (BLOCKED_HOSTNAMES.has(hostname)) throw new Error("Hostname is not allowed");
  if (hostname === "169.254.169.254" || hostname.endsWith(".internal") || hostname.endsWith(".local")) {
    throw new Error("Hostname is not allowed");
  }

  // Resolve and reject private/internal/cloud-metadata destinations (SSRF guard).
  try {
    const records = await dns.lookup(hostname, { all: true });
    if (records.length === 0) throw new Error("Hostname does not resolve");
    for (const r of records) {
      if (isPrivateIp(r.address)) throw new Error("Private or internal network destinations are not allowed");
    }
  } catch (e: any) {
    if (e?.message?.includes("not allowed")) throw e;
    throw new Error("Hostname does not resolve");
  }

  const normalized = `${u.protocol}//${hostname}${u.port && !["80", "443"].includes(u.port) ? ":" + u.port : ""}`;
  return { url: normalized, hostname, protocol: u.protocol as "http:" | "https:" };
}

export const SEVERITY_LABELS = ["info", "low", "medium", "high", "critical"] as const;
