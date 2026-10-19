import { decryptSecret } from "../lib/crypto.js";
import type { IntegrationAdapter } from "./types.js";
import { cloudflareFromCredentials } from "./cloudflare.js";
import { prisma } from "../db.js";

// Registry: honest construction. Returns null if the integration is not truly connected.
export async function getAdapter(integrationId: string): Promise<IntegrationAdapter | null> {
  const integ = await prisma.integration.findUnique({ where: { id: integrationId } });
  if (!integ || integ.status !== "CONNECTED" || !integ.credentialsEnc) return null;
  let creds: Record<string, string>;
  try { creds = JSON.parse(decryptSecret(integ.credentialsEnc)); }
  catch { return null; }
  switch (integ.kind) {
    case "CLOUDFLARE": return cloudflareFromCredentials(creds);
    // WAZUH, CROWDSEC, MODSECURITY, SURICATA adapters follow the same documented-API pattern.
    default: return null;
  }
}

export async function runHealthCheck(integrationId: string) {
  const integ = await prisma.integration.findUnique({ where: { id: integrationId } });
  if (!integ?.credentialsEnc) {
    return prisma.integration.update({ where: { id: integrationId },
      data: { status: "DISCONNECTED", lastHealthCheck: new Date(), lastError: "No credentials" } });
  }
  const adapter = await getAdapter(integrationId);
  if (!adapter) {
    return prisma.integration.update({ where: { id: integrationId },
      data: { status: "ERROR", lastHealthCheck: new Date(), lastError: "No adapter for kind (or disconnected)" } });
  }
  const creds = JSON.parse(decryptSecret(integ.credentialsEnc));
  const result = await adapter.healthCheck(creds);
  return prisma.integration.update({
    where: { id: integrationId },
    data: {
      status: result.ok ? "CONNECTED" : "ERROR",
      scopes: JSON.stringify(result.scopes),
      lastHealthCheck: new Date(),
      lastError: result.error ?? null,
    },
  });
}
