import { Router } from "express";
import { z } from "zod";
import crypto from "node:crypto";
import { prisma } from "../db.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requireWebsiteAccess } from "../middleware/tenant.js";
import { encryptSecret } from "../lib/crypto.js";
import { runHealthCheck } from "../integrations/index.js";
import { audit } from "../lib/audit.js";

export const integrationsRouter = Router();
integrationsRouter.use(requireAuth);

const KINDS = ["PUBLIC_MONITOR", "CLOUDFLARE", "WAZUH", "CROWDSEC", "MODSECURITY", "SURICATA", "APP_EVENTS"] as const;

integrationsRouter.get("/websites/:websiteId/integrations", requireWebsiteAccess, async (req, res) => {
  const items = await prisma.integration.findMany({ where: { websiteId: req.params.websiteId } });
  // Never expose credentials or their ciphertext to the browser.
  res.json(items.map(({ credentialsEnc, ...rest }) => ({ ...rest, hasCredentials: !!credentialsEnc })));
});

integrationsRouter.post("/websites/:websiteId/integrations", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const parsed = z.object({
    kind: z.enum(KINDS),
    credentials: z.record(z.string()).optional(),
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid integration" });
  const { kind, credentials } = parsed.data;

  if (kind === "PUBLIC_MONITOR") {
    // No credentials needed - but it still only only works on verified sites.
    const integ = await prisma.integration.create({
      data: { websiteId: req.params.websiteId, kind, status: "CONNECTED", scopes: JSON.stringify(["public:read"]) },
    });
    return res.json(integ);
  }
  if (kind === "APP_EVENTS") {
    // Issue an ingestion key (shown ONCE), store only its hash.
    const key = `sk_live_${crypto.randomBytes(24).toString("hex")}`;
    const keyHash = crypto.createHash("sha256").update(key).digest("hex");
    await prisma.integration.create({
      data: { websiteId: req.params.websiteId, kind, status: "CONNECTED",
              credentialsEnc: keyHash, scopes: JSON.stringify(["events:ingest"]) },
    });
    await audit(`user:${req.userId}`, "integration.created", req.params.websiteId, { kind });
    return res.json({ kind, ingestionKey: key, warning: "Store this key now - it will not be shown again." });
  }
  if (!credentials) return res.status(400).json({ error: "credentials required for this provider" });

  // Create as DISCONNECTED; only a real health check flips it to CONNECTED.
  const integ = await prisma.integration.create({
    data: { websiteId: req.params.websiteId, kind, status: "DISCONNECTED",
            credentialsEnc: encryptSecret(JSON.stringify(credentials)) },
  });
  const checked = await runHealthCheck(integ.id); // validates creds against the real API
  await audit(`user:${req.userId}`, "integration.connected", integ.id, { kind, status: checked.status });
  const { credentialsEnc, ...rest } = checked as any;
  res.json({ ...rest, hasCredentials: true });
});

integrationsRouter.post("/websites/:websiteId/integrations/:integrationId/health", requireWebsiteAccess, async (req, res) => {
  const updated = await runHealthCheck(req.params.integrationId);
  const { credentialsEnc, ...rest } = updated as any;
  res.json({ ...rest, hasCredentials: !!updated.credentialsEnc });
});

integrationsRouter.delete("/websites/:websiteId/integrations/:integrationId", requireWebsiteAccess, async (req, res) => {
  await prisma.integration.delete({ where: { id: req.params.integrationId } });
  res.json({ ok: true });
});
