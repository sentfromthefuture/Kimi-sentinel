import { Router } from "express";
import { prisma } from "../db.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requireWebsiteAccess } from "../middleware/tenant.js";
import { audit } from "../lib/audit.js";
import { executeAction } from "../services/actionController.js";
import { getAdapter } from "../integrations/index.js";

export const actionsRouter = Router();
actionsRouter.use(requireAuth);

actionsRouter.get("/websites/:websiteId/actions", requireWebsiteAccess, async (req, res) => {
  const actions = await prisma.defensiveAction.findMany({
    where: { websiteId: req.params.websiteId }, orderBy: { createdAt: "desc" }, take: 100,
  });
  res.json(actions);
});

// Human approval gate - the only path to executing high-impact actions.
actionsRouter.post("/actions/:actionId/approve", async (req: AuthedRequest, res) => {
  const action = await prisma.defensiveAction.findUnique({ where: { id: req.params.actionId }, include: { website: true } });
  if (!action || action.website.userId !== req.userId) return res.status(404).json({ error: "Not found" });
  if (action.status !== "AWAITING_APPROVAL") return res.status(409).json({ error: `Action is ${action.status}` });

  await prisma.$transaction([
    prisma.defensiveAction.update({ where: { id: action.id }, data: { status: "APPROVED", approvedBy: `user:${req.userId}` } }),
    prisma.approvalRequest.updateMany({ where: { actionId: action.id }, data: { status: "APPROVED", decidedBy: `user:${req.userId}`, decidedAt: new Date() } }),
  ]);
  await audit(`user:${req.userId}`, "action.approved", action.id, { type: action.type });

  const adapter = action.integrationId ? await getAdapter(action.integrationId) : null;
  if (!adapter) {
    await prisma.defensiveAction.update({ where: { id: action.id }, data: { status: "FAILED", error: "Integration no longer connected" } });
    return res.json({ id: action.id, status: "FAILED", reasons: ["Integration no longer connected"] });
  }
  const result = await executeAction(action.id, adapter);
  res.json(result);
});

actionsRouter.post("/actions/:actionId/deny", async (req: AuthedRequest, res) => {
  const action = await prisma.defensiveAction.findUnique({ where: { id: req.params.actionId }, include: { website: true } });
  if (!action || action.website.userId !== req.userId) return res.status(404).json({ error: "Not found" });
  await prisma.$transaction([
    prisma.defensiveAction.update({ where: { id: action.id }, data: { status: "REJECTED_POLICY" } }),
    prisma.approvalRequest.updateMany({ where: { actionId: action.id }, data: { status: "DENIED", decidedBy: `user:${req.userId}`, decidedAt: new Date() } }),
  ]);
  await audit(`user:${req.userId}`, "action.denied", action.id);
  res.json({ ok: true });
});

// Manual rollback of an active temporary rule.
actionsRouter.post("/actions/:actionId/rollback", async (req: AuthedRequest, res) => {
  const action = await prisma.defensiveAction.findUnique({ where: { id: req.params.actionId }, include: { website: true } });
  if (!action || action.website.userId !== req.userId) return res.status(404).json({ error: "Not found" });
  const adapter = action.integrationId ? await getAdapter(action.integrationId) : null;
  if (!adapter) return res.status(400).json({ error: "Integration not connected" });
  const result = await adapter.rollback(JSON.parse(action.params));
  await prisma.defensiveAction.update({
    where: { id: action.id },
    data: { status: "ROLLED_BACK", result: JSON.stringify(result.detail) },
  });
  await audit(`user:${req.userId}`, "action.rolled_back", action.id);
  res.json(result);
});
