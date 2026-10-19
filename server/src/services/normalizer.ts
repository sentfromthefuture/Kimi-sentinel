// Normalize raw events from any integration into a common shape. Treat all payloads as untrusted.
export interface NormalizedEvent {
  type: string;
  severity: number;
  sourceIp?: string;
  userAgent?: string;
  path?: string;
  userId?: string;
  sessionId?: string;
  timestamp: string;
  raw: Record<string, unknown>;
}

export function normalizeEvent(integrationKind: string, payload: unknown): NormalizedEvent {
  const p = (payload ?? {}) as Record<string, any>;
  const str = (v: unknown) => (typeof v === "string" ? v.slice(0, 512) : undefined);

  const typeMap: Record<string, string> = {
    failed_login: "failed_login", login_failed: "failed_login",
    password_reset: "password_reset_attempt",
    admin_endpoint: "endpoint_probe", endpoint_probe: "endpoint_probe",
    rate_limit: "rate_limit_hit", rate_limit_hit: "rate_limit_hit",
    malformed: "malformed_request", malformed_request: "malformed_request",
    session: "session_anomaly", session_anomaly: "session_anomaly",
    permission_denied: "permission_denied", file_upload: "file_upload_failure",
    api_rate: "rate_limit_hit", admin_change: "admin_change",
  };
  const rawType = str(p.type) ?? "unknown";
  const type = typeMap[rawType] ?? rawType;
  const sevMap: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const severity = typeof p.severity === "number" ? Math.min(4, Math.max(0, p.severity)) : (sevMap[str(p.severity) ?? ""] ?? 1);

  return {
    type,
    severity,
    sourceIp: str(p.sourceIp ?? p.ip ?? p.src),
    userAgent: str(p.userAgent ?? p.ua),
    path: str(p.path ?? p.url),
    userId: str(p.userId ?? p.user),
    sessionId: str(p.sessionId ?? p.session),
    timestamp: str(p.timestamp) ?? new Date().toISOString(),
    raw: {
      integration: integrationKind,
      // Keep only primitive fields from untrusted payloads; cap size.
      ...Object.fromEntries(
        Object.entries(p).filter(([, v]) => ["string", "number", "boolean"].includes(typeof v))
          .map(([k, v]) => [k.slice(0, 64), typeof v === "string" ? (v as string).slice(0, 512) : v])
      ),
    },
  };
}
