import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requireWebsiteAccess } from "../middleware/tenant.js";
import { validateTargetUrl } from "../lib/url.js";
import { audit } from "../lib/audit.js";
import { createVerification, checkVerification } from "../services/verification.js";
import { runBaselineAssessment } from "../services/baseline.js";
import { rateLimit } from "../middleware/rateLimit.js";

export const websitesRouter = Router();
websitesRouter.use(requireAuth);

const onboardLimiter = rateLimit({ windowMs: 3600_000, max: 20, key: (req) => `onboard:${(req as any).userId ?? req.ip}` });

websitesRouter.get("/", async (req: AuthedRequest, res) => {
  const websites = await prisma.website.findMany({
    where: { userId: req.userId },
    include: { integrations: true, _count: { select: { events: true, incidents: true } } },
    orderBy: { createdAt: "desc" },
  });
  res.json(websites);
});

websitesRouter.post("/", onboardLimiter, async (req: AuthedRequest, res) => {
  const parsed = z.object({ url: z.string().max(500), name: z.string().max(200).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "url is required" });

  // Strict URL + SSRF validation before anything touches the network.
  let target;
  try {
    target = await validateTargetUrl(parsed.data.url);
  } catch (e: any) {
    return res.status(400).json({ error: e.message });
  }

  const website = await prisma.website.create({
    data: { userId: req.userId!, url: target.url, hostname: target.hostname,
            name: parsed.data.name ?? target.hostname, status: "UNVERIFIED" },
  });
  await audit(`user:${req.userId}`, "website.created", website.id, { url: target.url });
  res.json(website);
});

websitesRouter.get("/:websiteId", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const website = await prisma.website.findUniqueOrThrow({
    where: { id: req.params.websiteId },
    include: { verifications: true, integrations: true },
  });
  res.json(website);
});

websitesRouter.delete("/:websiteId", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  await prisma.website.delete({ where: { id: req.params.websiteId } });
  await audit(`user:${req.userId}`, "website.deleted", req.params.websiteId);
  res.json({ ok: true });
});

// Operating mode changes are user-controlled, never agent-controlled.
websitesRouter.patch("/:websiteId/mode", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const parsed = z.object({ operatingMode: z.enum(["OBSERVER", "GUARDIAN", "INCIDENT_RESPONSE"]),
                            protectionLevel: z.enum(["WATCH", "MONITOR", "GUARDIAN"]).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid mode" });
  const website = await prisma.website.update({
    where: { id: req.params.websiteId },
    data: { operatingMode: parsed.data.operatingMode,
            protectionLevel: parsed.data.protectionLevel ?? undefined },
  });
  await audit(`user:${req.userId}`, "website.mode_changed", website.id, parsed.data);
  res.json(website);
});

// Emergency stop: suspends automated defensive actions, keeps monitoring + audit running.
websitesRouter.post("/:websiteId/emergency-stop", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const { on } = z.object({ on: z.boolean() }).parse(req.body ?? { on: true });
  await prisma.website.update({ where: { id: req.params.websiteId }, data: { emergencyStop: on } });
  await audit(`user:${req.userId}`, on ? "emergency_stop.on" : "emergency_stop.off", req.params.websiteId);
  res.json({ ok: true, emergencyStop: on });
});

// ---- Ownership verification ----
websitesRouter.post("/:websiteId/verification", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const parsed = z.object({ method: z.enum(["DNS_TXT", "FILE"]) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "method must be DNS_TXT or FILE" });
  const { verification, instructions } = await createVerification(req.params.websiteId, parsed.data.method);
  res.json({ verification, instructions });
});

websitesRouter.post("/:websiteId/verification/:verificationId/check", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const website = (req as any).website;
  const result = await checkVerification(req.params.verificationId, req.params.websiteId, website.url);
  res.json(result);
});

// ---- Safe baseline assessment (requires verified ownership) ----
websitesRouter.post("/:websiteId/baseline", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const website = (req as any).website;
  if (website.status !== "ACTIVE") {
    return res.status(403).json({ error: "Verify ownership before running assessments" });
  }
  const findings = await runBaselineAssessment(website.url);
  await prisma.website.update({ where: { id: website.id }, data: { lastMonitoredAt: new Date() } });
  await audit(`user:${req.userId}`, "baseline.run", website.id, { findings: findings.length });
  res.json({ findings, note: "Limited public visibility: these checks cannot detect attacks that leave no public signal." });
});
