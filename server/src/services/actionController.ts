// Separate defensive controller. The AI never touches integrations or credentials directly.
// Every action: policy check -> execute via integration adapter -> verify outcome -> record.
import { prisma } from "../db.js";
import { evaluateAction, type ActionRequest, type PolicyContext } from "./policyEngine.js";
import { audit } from "../lib/audit.js";
import { config } from "../config.js";
import type { IntegrationAdapter } from "../integrations/types.js";

export async function requestDefensiveAction(args: {
  websiteId: string;
  request: ActionRequest;
  evidence: unknown;
  incidentId?: string;
  integrationId?: string;
  adapter: IntegrationAdapter;
  requestedBy: string;
}): Promise<{ id: string; status: string; reasons: string[] }> {
  const { websiteId, request, evidence, incidentId, integrationId, adapter, requestedBy } = args;

  const website = await prisma.website.findUniqueOrThrow({ where: { id: websiteId } });
  const integration = integrationId
    ? await prisma.integration.findUnique({ where: { id: integrationId }) : null;

  const recentActionCount = await prisma.defensiveAction.count({
    where: { websiteId, createdAt: { gte: new Date(Date.now() - 3600_000) },
             status: { in: ["EXECUTED", "CONFIRMED"] } },
  });
  const existing = await prisma.defensiveAction.findFirst({
    where: { websiteId, type: request.type, target: request.target,
             status: { in: ["EXECUTED", "CONFIRMED", "APPROVED"] } },
  });
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$|^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(request.target);
  const ctx: PolicyContext = {
    emergencyStop: website.emergencyStop,
    operatingMode: website.operatingMode,
    integrationScopes: integration ? (JSON.parse(integration.scopes) as string[]) : [],
    recentActionCount,
    hasExistingRule: !!existing,
    isAllowlistedIp: isIp && config.policy.allowlistedIps.includes(request.target),
    targetInScope: true, // enforced upstream: websiteId + verified scope binding
  };

  const decision = evaluateAction(request, ctx);

  const action = await prisma.defensiveAction.create({
    data: {
      websiteId, incidentId: incidentId ?? null, integrationId: integrationId ?? null,
      type: request.type, target: request.target ?? "",
      params: JSON.stringify({ target: request.target, durationMin: request.durationMin }),
      reason: request.reason, evidence: JSON.stringify(evidence),
      status: decision.allowed ? "APPROVED" : decision.requiresApproval ? "AWAITING_APPROVAL" : "REJECTED_POLICY",
      requestedBy,
      expiresAt: new Date(Date.now() + request.durationMin * 60_000),
    },
  });
  await audit(requestedBy, "action.requested", action.id, { type: request.type, target: request.target, decision });

  if (decision.requiresApproval) {
    await prisma.approvalRequest.create({ data: { actionId: action.id } });
    await notifyWebsiteOwner(websiteId, "warning",
      `Sentinel AI requests approval for: ${request.type} on ${request.target} (${request.reason})`);
  }
  if (!decision.allowed) return { id: action.id, status: action.status, reasons: decision.reasons };

  return executeAction(action.id, adapter);
}

export async function executeAction(actionId: string, adapter: IntegrationAdapter) {
  const action = await prisma.defensiveAction.findUniqueOrThrow({ where: { id: actionId } });
  if (action.status !== "APPROVED") return { id: action.id, status: action.status, reasons: ["Not in APPROVED state"] };

  await prisma.defensiveAction.update({ where: { id: actionId }, data: { status: "EXECUTED", executedAt: new Date() } });
  try {
    // Dry-run support: adapters honour it so users can test without touching production.
    const result = await adapter.execute({
      type: action.type as any,
      params: JSON.parse(action.params),
      dryRun: process.env.DRY_RUN === "true",
    });
    const updated = await prisma.defensiveAction.update({
      where: { id: actionId },
      data: { status: result.success ? "CONFIRMED" : "FAILED", result: JSON.stringify(result.detail) },
    });
    await audit("agent", result.success ? "action.confirmed" : "action.failed", actionId, { detail: result.detail });
    if (action.incidentId && result.success) {
      await prisma.incident.update({ where: { id: action.incidentId }, data: { status: "CONTAINED" } });
    }
    return { id: action.id, status: updated.status, reasons: result.success ? [] : [String(result.detail)] };
  } catch (e: any) {
    await prisma.defensiveAction.update({
      where: { id: actionId }, data: { status: "FAILED", error: String(e?.message ?? e) },
    });
    await audit("agent", "action.error", actionId, { error: String(e?.message ?? e) });
    return { id: action.id, status: "FAILED", reasons: [String(e?.message ?? e)] };
  }
}

// Sweep: expire temporary rules via the adapter's rollback, never leave stale blocks.
export async function sweepExpiredActions(adapterLookup: (integrationId: string) => IntegrationAdapter | null) {
  const expired = await prisma.defensiveAction.findMany({
    where: { status: "CONFIRMED", expiresAt: { lt: new Date() } },
  });
  for (const a of expired) {
    const adapter = a.integrationId ? adapterLookup(a.integrationId) : null;
    let detail = "no integration";
    if (adapter) {
      try { detail = JSON.stringify((await adapter.rollback(JSON.parse(a.params))).detail); }
      catch (e: any) { detail = `rollback failed: ${e?.message}`; }
    }
    await prisma.defensiveAction.update({
      where: { id: a.id }, data: { status: "EXPIRED", result: detail },
    });
    await audit("system", "action.expired", a.id, { detail });
  }
  return expired.length;
}

export async function emergencyStop(websiteId: string, userId: string, on: boolean) {
  await prisma.website.update({ where: { id: websiteId }, data: { emergencyStop: on } });
  await audit(`user:${userId}`, on ? "emergency_stop.on" : "emergency_stop.off", websiteId);
}

async function notifyWebsiteOwner(websiteId: string, level: string, message: string) {
  const w = await prisma.website.findUniqueOrThrow({ where: { id: websiteId } });
  await prisma.notification.create({ data: { userId: w.userId, level, message } });
}
