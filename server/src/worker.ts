// Background worker: scheduled monitoring, investigation queue, rule expiry, notifications.
// Runs in the same process for dev convenience; in production run it as a separate service.
import { prisma } from "./db.js";
import { runBaselineAssessment } from "./services/baseline.js";
import { sweepExpiredActions } from "./services/actionController.js";
import { getAdapter } from "./integrations/index.js";
import { evaluateRules } from "./services/detector.js";
import { runInvestigation } from "./services/agent.js";

let running = false;
async function tick() {
  if (running) return;
  running = true;
  try {
    // 1. Expire temporary defensive rules (rollback via adapter).
    const adapters = new Map<string, any>();
    for (const i of await prisma.integration.findMany({ where: { status: "CONNECTED" } })) {
      const a = await getAdapter(i.id).catch(() => null); if (a) adapters.set(i.id, a);
    }
    await sweepExpiredActions((id) => adapters.get(id) ?? null);

    // 2. Scheduled public monitoring for sites with PUBLIC_MONITOR integration.
    const sites = await prisma.website.findMany({
      where: { status: "ACTIVE", integrations: { some: { kind: "PUBLIC_MONITOR", status: "CONNECTED" } } },
    });
    for (const site of sites) {
      try {
        await runBaselineAssessment(site.url);
        await prisma.website.update({ where: { id: site.id }, data: { lastMonitoredAt: new Date() } });
      } catch (e: any) {
        await prisma.notification.create({ data: { userId: site.userId, level: "warning",
          message: `Monitoring check failed for ${site.hostname}: ${e?.message}. Missing telemetry is not evidence of safety.` } });
      }
    }

    // 3. Re-evaluate detection rules across active sites; investigate on new hits.
    for (const site of sites) {
      const hits = await evaluateRules(site.id, 10);
      if (hits.length > 0) {
        const recent = await prisma.securityEvent.findFirst({
          where: { websiteId: site.id, investigations: { none: {} } }, orderBy: { receivedAt: "desc" } });
        if (recent) await runInvestigation(recent.id).catch(() => {});
      }
    }
  } finally {
    running = false;
  }
}

export function startWorker(intervalMs = 60_000) {
  setInterval(() => tick().catch(console.error), intervalMs);
  console.log(`[worker] started (interval ${intervalMs}ms, dry-run: ${process.env.DRY_RUN === "true"})`);
}
