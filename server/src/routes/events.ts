import { Router } from "express";
import crypto from "node:crypto";
import { z } from "zod";
import { prisma } from "../db.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requireWebsiteAccess } from "../middleware/tenant.js";
import { ingestEvent, runInvestigation } from "../services/agent.js";
import { DEMO_SCENARIOS, generateDemoEvents } from "../services/demo.js";
import { rateLimit } from "../middleware/rateLimit.js";

export const eventsRouter = Router();

// ---- Secure event-ingestion API ----
// Apps POST events with a per-website ingestion key. Keys are stored hashed,
// sent as Bearer tokens. Source is always labelled REAL unless marked test.
export const ingestRouter = Router();

ingestRouter.post("/:websiteId/events", rateLimit({ windowMs: 60_000, max: 600 }), async (req, res) => {
  const key = (req.headers.authorization ?? "").replace(/^Bearer /, "");
  if (!key) return res.status(401).json({ error: "Missing ingestion key" });
  const keyHash = crypto.createHash("sha256").update(key).digest("hex");
  const website = await prisma.website.findFirst({
    where: { id: req.params.websiteId, verifications: { some: { status: "VERIFIED" } } },
    include: { integrations: true },
  });
  if (!website) return res.status(404).json({ error: "Website not found or not verified" });

  // The ingestion credential lives on the APP_EVENTS integration for this site.
  const appInteg = website.integrations.find((i) => i.kind === "APP_EVENTS");
  if (!appInteg?.credentialsEnc) return res.status(403).json({ error: "Event ingestion not enabled for this website" });
  const { createDecipheriv } = await import("node:crypto");
  // Compare against stored hash of the ingestion key instead of decrypting.
  const storedHash = appInteg.credentialsEnc.split(".")[0]; // we store hash in the first slot for key rows
  const provided = crypto.createHash("sha256").update(key).digest("hex");
  if (provided !== storedHash) return res.status(401).json({ error: "Invalid ingestion key" });

  const parsed = z.object({
    source: z.enum(["REAL", "TEST"]).default("REAL"),
    events: z.array(z.record(z.unknown())).max(100),
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid event payload (max 100 events)" });

  const results = [];
  for (const raw of parsed.data.events) {
    const r = await ingestEvent({
      websiteId: website.id,
      integrationId: appInteg.id,
      source: parsed.data.source as "REAL" | "TEST",
      raw,
    });
    results.push(r);
  }
  res.json({ ingested: results.length, results });
});

// ---- Authenticated read APIs ----
eventsRouter.use(requireAuth);

eventsRouter.get("/websites/:websiteId/events", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const take = Math.min(Number(req.query.take ?? 100), 500);
  const events = await prisma.securityEvent.findMany({
    where: { websiteId: req.params.websiteId },
    orderBy: { receivedAt: "desc" }, take,
  });
  res.json(events);
});

// ---- Demonstration mode (clearly labelled simulated data) ----
eventsRouter.get("/demo/scenarios", (_req, res) => res.json(DEMO_SCENARIOS));

eventsRouter.post("/websites/:websiteId/demo", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const parsed = z.object({ scenario: z.string().max(50), count: z.number().int().min(1).max(50).default(10) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid scenario" });
  const events = generateDemoEvents(parsed.data.scenario, parsed.data.count);
  const results = [];
  for (const raw of events) {
    const r = await ingestEvent({ websiteId: req.params.websiteId, source: "SIMULATED", raw });
    if (!r.deduplicated) {
      const { incidentId } = await runInvestigation(r.eventId);
      results.push({ ...r, incidentId });
    } else results.push(r);
  }
  res.json({ simulated: true, label: "SIMULATED EVENTS - demonstration only, not real monitoring", results });
});

// Threat intel lookup (authenticated)
eventsRouter.get("/websites/:websiteId/threat-intel/:ip", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const { lookupIp } = await import("../services/threatIntel.js");
  const results = await lookupIp(req.params.ip);
  res.json({ target: req.params.ip, results, note: "Reputation is signal, not proof. Never blocks automatically." });
});
