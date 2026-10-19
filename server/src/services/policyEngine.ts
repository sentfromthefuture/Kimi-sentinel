// THE core safety principle: the AI investigates and proposes; this deterministic
// engine decides. The agent can never bypass, modify, or disable these checks.
import { config } from "../config.js";

export interface ActionRequest {
  type: "rate_limit" | "block_ip" | "revoke_session" | "challenge" | "notify";
  target: string;
  durationMin: number;
  reason: string;
  evidence: string[];
  confidence: number;
  severity: number;
}

export interface PolicyContext {
  emergencyStop: boolean;
  operatingMode: string;          // OBSERVER | GUARDIAN | INCIDENT_RESPONSE
  integrationScopes: string[];
  recentActionCount: number;
  hasExistingRule: boolean;
  isAllowlistedIp: boolean;
  targetInScope: boolean;
}

export interface PolicyDecision { allowed: boolean; requiresApproval: boolean; reasons: string[]; }

const APPROVAL_ALWAYS = new Set(["block_ip", "revoke_session"]);

export function evaluateAction(req: ActionRequest, ctx: PolicyContext): PolicyDecision {
  const hard: string[] = [];   // can never be overridden
  const soft: string[] = [];   // resolvable via human approval

  if (ctx.emergencyStop) hard.push("Emergency stop is active");
  if (!ctx.targetInScope) hard.push("Target is outside the verified website scope");
  if (ctx.isAllowlistedIp) hard.push("Target is on the protected/allowlisted IP list");
  if (ctx.hasExistingRule) hard.push("A conflicting defensive rule already exists");
  if (req.durationMin > config.policy.maxAutoActionDurationMin)
    hard.push(`Duration ${req.durationMin}m exceeds max ${config.policy.maxAutoActionDurationMin}m`);
  if (ctx.recentActionCount >= config.policy.actionRateLimitPerHour)
    hard.push("Hourly defensive action rate limit reached");
  if (req.confidence < 0.5) hard.push("Confidence below minimum threshold (0.5)");
  if (req.severity < 1) hard.push("Severity too low for any defensive action");
  if (!req.reason || req.reason.length < 10) hard.push("Insufficiently documented reason");

  const requiredScope: Record<string, string> = {
    rate_limit: "rules:write", block_ip: "rules:write",
    revoke_session: "sessions:write", challenge: "auth:challenge", notify: "notifications:send",
  };
  if (!ctx.integrationScopes.includes(requiredScope[req.type] ?? ""))
    hard.push(`Integration lacks required scope: ${requiredScope[req.type]}`);

  if (ctx.operatingMode === "OBSERVER") {
    hard.push("Observer mode: agent may only recommend, never execute");
  } else if (ctx.operatingMode === "GUARDIAN") {
    if (req.confidence < config.policy.minConfidenceAuto || req.severity < config.policy.minSeverityAuto)
      soft.push(`Below Guardian auto-execution thresholds (confidence ${config.policy.minConfidenceAuto}, severity ${config.policy.minSeverityAuto})`);
  }
  // In every mode, high-impact actions need a human. In Incident Response they must
  // have been pre-authorized by creating an ApprovalRequest - enforced in the controller.
  if (APPROVAL_ALWAYS.has(req.type)) soft.push("High-impact action requires human approval");

  if (hard.length > 0)
    return { allowed: false, requiresApproval: false, reasons: [...hard, ...soft] };
  if (soft.length > 0)
    return { allowed: false, requiresApproval: true, reasons: soft };
  return { allowed: true, requiresApproval: false, reasons: [] };
}
