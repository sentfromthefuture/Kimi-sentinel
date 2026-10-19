// Deterministic rule-based detection. The AI never replaces these rules -
// it reasons on top of the events and rule hits they produce.
import { prisma } from "../db.js";

export interface RuleHit { rule: string; description: string; severity: number; evidence: string; }

export async function evaluateRules(websiteId: string, windowMin = 10): Promise<RuleHit[]> {
  const since = new Date(Date.now() - windowMin * 60_000);
  const events = await prisma.securityEvent.findMany({
    where: { websiteId, receivedAt: { gte: since } },
    orderBy: { receivedAt: "asc" },
  });
  const hits: RuleHit[] = [];
  const by = (t: string) => events.filter((e) => e.type === t);

  // R1: brute force - >= 8 failed logins from one IP in window
  const loginFails = by("failed_login");
  const ipCounts = new Map<string, number>();
  for (const e of loginFails) if (e.sourceIp) ipCounts.set(e.sourceIp, (ipCounts.get(e.sourceIp) ?? 0) + 1);
  for (const [ip, n] of ipCounts) {
    if (n >= 8) hits.push({
      rule: "BRUTE_FORCE", severity: 3,
      description: `Repeated failed logins from ${ip}`,
      evidence: `${n} failed logins in ${windowMin} min`,
    });
  }

  // R2: admin endpoint probing - >= 5 requests to admin paths from one IP
  const probes = by("endpoint_probe");
  const probeCounts = new Map<string, number>();
  for (const e of probes) if (e.sourceIp) probeCounts.set(e.sourceIp, (probeCounts.get(e.sourceIp) ?? 0) + 1);
  for (const [ip, n] of probeCounts) {
    if (n >= 5) hits.push({
      rule: "ADMIN_PROBE", severity: 3,
      description: `Suspicious discovery of administrative endpoints from ${ip}`,
      evidence: `${n} admin-path requests in ${windowMin} min`,
    });
  }

  // R3: excessive API requests - >= 300 events from one IP in window
  const allCounts = new Map<string, number>();
  for (const e of events) if (e.sourceIp) allCounts.set(e.sourceIp, (allCounts.get(e.sourceIp) ?? 0) + 1);
  for (const [ip, n] of allCounts) {
    if (n >= 300) hits.push({
      rule: "EXCESSIVE_REQUESTS", severity: 2,
      description: `Excessive request volume from ${ip}`,
      evidence: `${n} events in ${windowMin} min`,
    });
  }

  // R4: credential stuffing pattern - failures across many distinct user accounts from one IP
  const acctMap = new Map<string, Set<string>>();
  for (const e of loginFails) {
    if (!e.sourceIp) continue;
    const payload = JSON.parse(e.payload);
    const acct = payload.userId ?? payload.username ?? "unknown";
    if (!acctMap.has(e.sourceIp)) acctMap.set(e.sourceIp, new Set());
    acctMap.get(e.sourceIp)!.add(acct);
  }
  for (const [ip, accts] of acctMap) {
    if (accts.size >= 5) hits.push({
      rule: "CREDENTIAL_STUFFING", severity: 4,
      description: `Failed logins against ${accts.size} distinct accounts from ${ip}`,
      evidence: `Accounts targeted: ${accts.size} in ${windowMin} min`,
    });
  }

  // R5: malformed request burst - possible scanner
  const malformed = by("malformed_request");
  const mfCounts = new Map<string, number>();
  for (const e of malformed) if (e.sourceIp) mfCounts.set(e.sourceIp, (mfCounts.get(e.sourceIp) ?? 0) + 1);
  for (const [ip, n] of mfCounts) {
    if (n >= 10) hits.push({
      rule: "MALFORMED_BURST", severity: 2,
      description: `Malformed request burst from ${ip}`,
      evidence: `${n} malformed requests in ${windowMin} min`,
    });
  }

  // R6: session anomaly following login failures (account compromise signal)
  const anomalies = by("session_anomaly");
  for (const a of anomalies) {
    const payload = JSON.parse(a.payload);
    if (payload.sessionId) {
      const priorFails = loginFails.filter((f) => {
        const fp = JSON.parse(f.payload);
        return fp.userId && fp.userId === payload.userId;
      }).length;
      if (priorFails > 0) hits.push({
        rule: "SESSION_AFTER_FAILURES", severity: 3,
        description: `Unusual session activity after login failures for user ${payload.userId}`,
        evidence: `sessionId=${payload.sessionId}, ${priorFails} prior failures`,
      });
    }
  }
  return hits;
}
