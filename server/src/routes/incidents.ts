import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requireWebsiteAccess } from "../middleware/tenant.js";
import { audit } from "../lib/audit.js";

export const incidentsRouter = Router();
incidentsRouter.use(requireAuth);

incidentsRouter.get("/websites/:websiteId/incidents", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const incidents = await prisma.incident.findMany({
    where: { websiteId: req.params.websiteId },
    include: { investigations: { orderBy: { createdAt: "desc" }, take: 1 }, actions: true },
    orderBy: { startedAt: "desc" }, take: 100,
  });
  res.json(incidents);
});

incidentsRouter.get("/incidents/:incidentId", async (req: AuthedRequest, res) => {
  const incident = await prisma.incident.findUnique({
    where: { id: req.params.incidentId },
    include: {
      investigations: true,
      actions: { include: { approval: true } },
      events: { orderBy: { receivedAt: "asc" }, take: 300 },
      website: true,
    },
  });
  if (!incident || incident.website.userId !== req.userId) return res.status(404).json({ error: "Incident not found" });
  res.json(incident);
});

// User feedback loop: correct the agent via controlled status changes, never free-form rule edits.
incidentsRouter.patch("/incidents/:incidentId", async (req: AuthedRequest, res) => {
  const parsed = z.object({
    status: z.enum(["NEW", "INVESTIGATING", "CONTAINED", "AWAITING_APPROVAL", "RESOLVED", "FALSE_POSITIVE"]),
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid status" });
  const incident = await prisma.incident.findUnique({ where: { id: req.params.incidentId }, include: { website: true } });
  if (!incident || incident.website.userId !== req.userId) return res.status(404).json({ error: "Incident not found" });
  const updated = await prisma.incident.update({
    where: { id: incident.id },
    data: { status: parsed.data.status, resolvedAt: ["RESOLVED", "FALSE_POSITIVE"].includes(parsed.data.status) ? new Date() : null },
  });
  await audit(`user:${req.userId}`, "incident.status_changed", incident.id, { status: parsed.data.status });
  res.json(updated);
});

// Agent decisions feed (the "latest agent decisions" overview widget)
incidentsRouter.get("/websites/:websiteId/decisions", requireWebsiteAccess, async (req: AuthedRequest, res) => {
  const decisions = await prisma.agentDecision.findMany({
    where: { websiteId: req.params.websiteId }, orderBy: { createdAt: "desc" }, take: 50,
  });
  res.json(decisions.map((d) => ({ ...d, decision: JSON.parse(d.decision) })));
});
