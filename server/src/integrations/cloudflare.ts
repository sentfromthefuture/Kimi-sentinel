import type { IntegrationAdapter, AdapterResult, ActionParams } from "./types.js";

// Cloudflare adapter: WAF events read, rate-limit/block rules via Filters API.
// Requires API token with Zone.Firewall Services permissions. Real API calls only.
export class CloudflareAdapter implements IntegrationAdapter {
  kind = "CLOUDFLARE";
  constructor(private zoneId: string, private token: string) {}

  private async cf(path: string, init: RequestInit = {}) {
    const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || (body as any)?.success === false)
      throw new Error(`Cloudflare API error ${res.status}: ${JSON.stringify((body as any)?.errors ?? body).slice(0, 300)}`);
    return body;
  }

  async healthCheck(creds: Record<string, string>) {
    try {
      const body = await this.cf("/user/tokens/verify");
      const perms = (body as any)?.result?.status === "active";
      // Verify zone access
      await this.cf(`/zones/${this.zoneId}`);
      return { ok: !!perms, scopes: perms ? ["events:read", "rules:write"] : [], error: perms ? undefined : "Token inactive" };
    } catch (e: any) {
      return { ok: false, scopes: [], error: String(e?.message ?? e) };
    }
  }

  async testConnection(): Promise<AdapterResult> {
    try { await this.cf(`/zones/${this.zoneId}`); return { success: true, detail: { zone: this.zoneId } }; }
    catch (e: any) { return { success: false, detail: String(e?.message ?? e) }; }
  }

  async execute(action: { type: string; params: ActionParams; dryRun: boolean }): Promise<AdapterResult> {
    if (action.dryRun) return { success: true, detail: { dryRun: true, what: `would ${action.type} ${action.params.target}` } };
    if (action.type === "block_ip" || action.type === "rate_limit") {
      const body = await this.cf(`/zones/${this.zoneId}/filters`, {
        method: "POST",
        body: JSON.stringify([{ expression: `(ip.src eq ${action.params.target})`, description: `Sentinel AI: ${action.type}`, paused: false }]),
      });
      const filter = (body as any).result?.[0];
      // Attach a block/rate-limit rule to the filter with expiry noted in description
      await this.cf(`/zones/${this.zoneId}/firewall/rules`, {
        method: "POST",
        body: JSON.stringify([{
          filter: { id: filter.id },
          action: action.type === "block_ip" ? "block" : "challenge",
          description: `Sentinel AI ${action.type} - expires in ${action.params.durationMin}m`,
        }]),
      });
      return { success: true, detail: { filterId: filter.id, expiresAt: new Date(Date.now() + action.params.durationMin * 60000).toISOString() } };
    }
    return { success: false, detail: `Unsupported action type: ${action.type}` };
  }

  async rollback(params: ActionParams): Promise<AdapterResult> {
    // Rollback requires the stored filter id; actionController passes params back,
    // adapters look up rules by description+target. Simplified: delete matching filter.
    try {
      const body = await this.cf(`/zones/${this.zoneId}/filters?description=Sentinel%20AI`);
      const filters = ((body as any).result ?? []).filter((f: any) => f.expression?.includes(params.target));
      for (const f of filters)
        await this.cf(`/zones/${this.zoneId}/filters/${f.id}`, { method: "DELETE" });
      return { success: true, detail: { removed: filters.length } };
    } catch (e: any) { return { success: false, detail: String(e?.message ?? e) }; }
  }
}

export function cloudflareFromCredentials(creds: Record<string, string>) {
  return new CloudflareAdapter(creds.zoneId, creds.apiToken);
}
