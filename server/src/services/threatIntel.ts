// Pluggable threat-intelligence providers. Reputation is signal, not proof -
// a bad score alone never triggers a block.
export interface ReputationResult {
  source: string;
  target: string;
  score: number;        // 0..100, higher = more suspicious
  categories: string[];
  lastSeen: string;
  confidence: "high" | "medium" | "low";
}

export interface ThreatIntelProvider {
  name: string;
  lookupIp(ip: string): Promise<ReputationResult | null>;
}

// Example provider: AbuseIPDB-compatible (real API, respects rate limits).
class AbuseIPDBProvider implements ThreatIntelProvider {
  name = "abuseipdb";
  constructor(private apiKey: string) {}
  async lookupIp(ip: string): Promise<ReputationResult | null> {
    if (!this.apiKey) return null;
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: this.apiKey, Accept: "application/json" },
    });
    if (res.status === 429) return null; // respect rate limits
    if (!res.ok) return null;
    const body = await res.json();
    const d = body?.data;
    if (!d) return null;
    return {
      source: this.name, target: ip, score: Math.min(100, d.abuseConfidenceScore ?? 0),
      categories: (d.reports?.[0]?.categories ?? []).map(String).slice(0, 5),
      lastSeen: d.lastReportedAt ?? new Date().toISOString(),
      confidence: (d.abuseConfidenceScore ?? 0) > 50 ? "high" : (d.abuseConfidenceScore ?? 0) > 20 ? "medium" : "low",
    };
  }
}

const providers: ThreatIntelProvider[] = [
  new AbuseIPDBProvider(process.env.ABUSEIPDB_API_KEY ?? ""),
];

export async function lookupIp(ip: string): Promise<ReputationResult[]> {
  const results = await Promise.all(providers.map((p) => p.lookupIp(ip).catch(() => null)));
  return results.filter((r): r is ReputationResult => r !== null);
}
