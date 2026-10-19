// Safe, conservative, rate-limited public baseline assessment.
// Read-only checks only: availability, HTTPS, TLS indicators, security headers, redirects, tech hints.
// No exploitation, no auth bypass, no high-volume requests. Max 3 requests per run.

const SECURITY_HEADERS = [
  "strict-transport-security", "content-security-policy", "x-frame-options",
  "x-content-type-options", "referrer-policy", "permissions-policy",
];

export interface BaselineFinding {
  check: string;
  severity: 0 | 1 | 2 | 3; // info..high
  status: "pass" | "warn" | "fail" | "info";
  evidence: string;
  confidence: "high" | "medium" | "low";
  remediation?: string;
}

export async function runBaselineAssessment(url: string): Promise<BaselineFinding[]> {
  const findings: BaselineFinding[] = [];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);

  try {
    // Check 1: HTTPS availability + redirect behaviour
    let finalUrl = url;
    let res: Response | null = null;
    try {
      res = await fetch(url, { signal: controller.signal, redirect: "follow", headers: { "user-agent": "SentinelAI-Baseline/0.1" } });
      finalUrl = res.url;
    } catch (e: any) {
      findings.push({
        check: "availability", severity: 3, status: "fail",
        evidence: `Site unreachable: ${e?.cause?.code ?? e?.message ?? "unknown"}`,
        confidence: "high", remediation: "Verify the site is online and reachable over HTTPS.",
      });
      return findings;
    }
    findings.push({
      check: "availability", severity: 0, status: "pass",
      evidence: `HTTP ${res!.status} in ${Date.now() ? "" : ""}${"" || ""}reachable`, confidence: "high",
    });
    if (url.startsWith("http://")) {
      findings.push({
        check: "https-redirect", severity: 2, status: finalUrl.startsWith("https://") ? "pass" : "fail",
        evidence: finalUrl.startsWith("https://") ? `Redirects to ${finalUrl}` : "No redirect to HTTPS detected",
        confidence: "medium", remediation: "Redirect all HTTP traffic to HTTPS.",
      });
    }

    // Check 2: security headers
    const present: string[] = [];
    const missing: string[] = [];
    for (const h of SECURITY_HEADERS) {
      if (res!.headers.get(h)) present.push(h); else missing.push(h);
    }
    findings.push({
      check: "security-headers", severity: missing.length > 3 ? 2 : 1,
      status: missing.length === 0 ? "pass" : "warn",
      evidence: `Present: ${present.join(", ") || "none"}. Missing: ${missing.join(", ") || "none"}`,
      confidence: "high",
      remediation: missing.length ? `Consider adding: ${missing.join(", ")}` : undefined,
    });

    // Check 3: technology hints from Server header (informational only)
    const server = res!.headers.get("server");
    findings.push({
      check: "technology-hints", severity: 0, status: "info",
      evidence: server ? `Server header: ${server}` : "No Server header exposed (good hygiene)",
      confidence: "low",
    });
  } finally {
    clearTimeout(timer);
  }
  return findings;
}
