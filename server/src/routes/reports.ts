import { Router } from "express";
import { prisma } from "../db.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requireWebsiteAccess } from "../middleware/tenant.js";

export const reportsRouter = Router();
reportsRouter.use(requireAuth);

reportsRouter.get("/websites/:websiteId/report", requireWebsiteAccess, async (req, res) => {
  const days = Math.min(Number(req.query.days ?? 7), 90);
  const since = new Date(Date.now() - days * 86400_000);
  const wid = req.params.websiteId;
  const [events, incidents, actions, integrations, falsePositives, failures] = await Promise.all([
    prisma.securityEvent.groupBy({ by: ["type"], where: { websiteId: wid, receivedAt: { gte: since } }, _count: true }),
    prisma.incident.findMany({ where: { websiteId: wid, startedAt: { gte: since } }, include: { investigations: true, actions: true } }),
    prisma.defensiveAction.findMany({ where: { websiteId: wid, createdAt: { gte: since } } }),
    prisma.integration.findMany({ where: { websiteId: wid } }),
    prisma.incident.count({ where: { websiteId: wid, status: "FALSE_POSITIVE", startedAt: { gte: since } } }),
    prisma.integration.count({ where: { websiteId: wid, status: { in: ["ERROR", "DISCONNECTED"] } } }),
  ]);
  const unresolved = incidents.filter((i) => !["RESOLVED", "FALSE_POSITIVE"].includes(i.status)).length;
  const byStatus: Record<string, number> = {};
  for (const a of actions) byStatus[a.status] = (byStatus[a.status] ?? 0) + 1;
  res.json({
    periodDays: days,
    eventsByType: events,
    incidentCount: incidents.length, unresolved,
    incidents: incidents.map((i) => ({ id: i.id, title: i.title, severity: i.severity, status: i.status,
      classification: i.investigations[0]?.classification ?? null,
      actions: i.actions.map((a) => ({ type: a.type, status: a.status })) })),
    actionsByStatus: byStatus,
    falsePositives,
    integrationHealth: integrations.map(({ credentialsEnc, ...i }: any) => i),
    monitoringFailures: failures,
    recommendations: [
      failures > 0 ? "Reconnect failed integrations - missing telemetry is not proof of safety." : null,
      unresolved > 0 ? `${unresolved} incident(s) unresolved - review Investigations.` : null,
      integrations.every((i) => !(JSON.parse(i.scopes) as string[]).includes("rules:write"))
        ? "No integration has defensive permissions. Connect a WAF with rules:write to enable Active Guardian." : null,
    ].filter(Boolean),
    coverageNote: "External Watch provides limited public visibility only; threats without public signals are invisible at this level.",
  });
});

export const notificationsRouter = Router();
notificationsRouter.use(requireAuth);
notificationsRouter.get("/", async (req: AuthedRequest, res) => {
  res.json(await prisma.notification.findMany({ where: { userId: req.userId }, orderBy: { createdAt: "desc" }, take: 50 }));
});
notificationsRouter.post("/:id/read", async (req: AuthedRequest, res) => {
  await prisma.notification.updateMany({ where: { id: req.params.id, userId: req.userId }, data: { read: true } });
  res.json({ ok: true });
});
