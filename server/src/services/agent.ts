// The autonomous agent: ingest -> normalize -> correlate -> rule-detect ->
// investigate (AI) -> propose action -> policy engine -> controller -> monitor.
// Records every decision. The agent never grants itself permissions.
import { prisma } from "../db.js";
import { normalizeEvent } from "./normalizer.js";
import { evaluateRules } from "./detector.js";
import { investigate } from "./investigator.js";
import { lookupIp } from "./threatIntel.js";
import { requestDefensiveAction } from "./actionController.js";
import { getAdapter } from "../integrations/index.js";
import { audit } from "../lib/audit.js";
import { createHash } from "node:crypto";

export async function ingestEvent(args: {
  websiteId: string;
  integrationId?: string;
  source: "REAL" | "SIMULATED" | "TEST";
  raw: unknown;
}): Promise<{ eventId: string; deduplicated: boolean }> {
  const integration = args.integrationId
    ? await prisma.integration.findUnique({ where: { id: args.integrationId } }) : null;
  const normalized = normalizeEvent(integration?.kind ?? "APP_EVENTS", args.raw);
  const fingerprint = createHash("sha256")
    .update(JSON.stringify([args.websiteId, normalized.type, normalized.sourceIp, normalized.path, Math.floor(Date.parse(normalized.timestamp) / 60_000)]))
    .digest("hex").slice(0, 32);

  // Deduplication
  const existing = await prisma.securityEvent.findFirst({ where: { fingerprint } });
  if (existing) return { eventId: existing.id, deduplicated: true };

  const event = await prisma.securityEvent.create({
    data: {
      websiteId: args.websiteId,
      integrationId: args.integrationId ?? null,
      source: args.source,
      type: normalized.type,
      severity: normalized.severity,
      sourceIp: normalized.sourceIp ?? null,
      payload: JSON.stringify(normalized),
      fingerprint,
    },
  });
  await audit("agent", "event.ingested", event.id, { type: normalized.type, source: args.source });
  return { eventId: event.id, deduplicated: false };
}

// Main investigation pipeline for one event (invoked by the background worker).
export async function runInvestigation(eventId: string) {
  const event = await prisma.securityEvent.findUniqueOrThrow({
    where: { id: eventId }, include: { website: true },
  });

  // Correlate: pull related recent events for timeline-based evaluation.
  const since = new Date(Date.now() - 10 * 60_000);
  const related = await prisma.securityEvent.findMany({
    where: { websiteId: event.websiteId, receivedAt: { gte: since }, id: { not: event.id } },
    take: 200, orderBy: { receivedAt: "desc" },
  });

  const ruleHits = await evaluateRules(event.websiteId, 10);
  const relatedNorm = related.map((r) => {
    const p = JSON.parse(r.payload);
    return { type: r.type, sourceIp: r.sourceIp ?? undefined, path: p.path, receivedAt: r.receivedAt.toISOString() };
  });

  const { output, provider, fallbackUsed } = await investigate({
    eventType: event.type,
    severity: event.severity,
    sourceIp: event.sourceIp ?? undefined,
    ruleHits,
    relatedEvents: relatedNorm,
    context: { websiteUrl: event.website.url, operatingMode: event.website.operatingMode },
  });

  // Threat-intel enrichment (signal only, never auto-block on reputation alone)
  let intel: unknown[] = [];
  if (event.sourceIp) {
    intel = await lookupIp(event.sourceIp).catch(() => []);
  }

  const incident = await prisma.incident.create({
    data: {
      websiteId: event.websiteId,
      title: `${event.type} from ${event.sourceIp ?? "unknown source"}`,
      severity: output.classification === "confirmed_threat" ? Math.max(event.severity, 3) : event.severity,
      status: output.classification === "benign" ? "RESOLVED" : "INVESTIGATING",
    },
  });
  await prisma.securityEvent.update({ where: { id: event.id }, data: {} });

  const investigation = await prisma.investigation.create({
    data: {
      incidentId: incident.id,
      eventId: event.id,
      status: "COMPLETE",
      aiProvider: provider + (fallbackUsed ? " (fallback)" : ""),
      explanation: output.explanation,
      classification: output.classification,
      confidence: output.confidence,
      recommendedAction: output.recommendedAction === "none" ? null : output.recommendedAction,
      evidence: JSON.stringify({ ruleHits, correlatedEvents: relatedNorm.length, threatIntel: intel }),
      actionRequest: output.recommendedAction !== "none" ? JSON.stringify({
        type: output.recommendedAction,
        target: output.actionTarget ?? event.sourceIp,
        durationMin: output.actionDurationMin ?? 30,
        reason: output.reasoning.join("; "),
        evidence: output.reasoning,
        confidence: output.confidence,
        severity: event.severity,
      }) : null,
    },
  });

  await prisma.agentDecision.create({
    data: { websiteId: event.websiteId, mode: event.website.operatingMode,
            decision: JSON.stringify({ eventId, incidentId: incident.id, classification: output.classification, confidence: output.confidence, recommendedAction: output.recommendedAction }) },
  });

  // If the agent recommends a defensive action, route it through the policy engine + controller.
  if (output.recommendedAction !== "none" && output.actionTarget) {
    const wafIntegration = await prisma.integration.findFirst({
      where: { websiteId: event.websiteId, status: "CONNECTED", kind: { in: ["CLOUDFLARE", "WAZUH", "CROWDSEC"] } },
    });
    const adapter = wafIntegration ? await getAdapter(wafIntegration.id) : null;
    if (wafIntegration && adapter) {
      await requestDefensiveAction({
        websiteId: event.websiteId,
        request: {
          type: output.recommendedAction as any,
          target: output.actionTarget,
          durationMin: output.actionDurationMin ?? 30,
          reason: output.reasoning.join("; "),
          evidence: output.reasoning,
          confidence: output.confidence,
          severity: event.severity,
        },
        evidence: { investigationId: investigation.id, ruleHits },
        incidentId: incident.id,
        integrationId: wafIntegration.id,
        adapter,
        requestedBy: "agent",
      });
    } else {
      // Honest state: no defensive integration available -> recommend only, notify owner.
      await prisma.notification.create({
        data: { userId: event.website.userId, level: "warning",
                message: `Sentinel recommends "${output.recommendedAction}" for ${output.actionTarget}, but no defensive integration is connected. Connect a WAF integration to enable Active Guardian.` },
      });
      await audit("agent", "action.skipped_no_integration", incident.id, { recommended: output.recommendedAction });
    }
  }

  await audit("agent", "investigation.complete", investigation.id, {
    classification: output.classification, confidence: output.confidence,
  });
  return { incidentId: incident.id, investigationId: investigation.id };
}
