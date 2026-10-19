// Demonstration mode: clearly-labelled simulated events for a sandbox website.
// Every event has source=SIMULATED and is never presented as real monitoring.
import { randomBytes } from "node:crypto";

export const DEMO_SOURCE_IPS = ["203.0.113.10", "203.0.113.77", "198.51.100.44"];

export function generateDemoEvents(scenario: string, count: number): unknown[] {
  const ip = DEMO_SOURCE_IPS[Math.floor(Math.random() * DEMO_SOURCE_IPS.length)];
  const now = Date.now();
  const events: any[] = [];
  const mk = (type: string, severity: number, extra: any = {}, i = 0) => ({
    type, severity, sourceIp: ip, timestamp: new Date(now - i * 1000).toISOString(),
    userAgent: "sentinel-demo-generator/0.1", ...extra,
  });

  switch (scenario) {
    case "brute_force":
      for (let i = 0; i < Math.min(count, 12); i++)
        events.push(mk("failed_login", 2, { userId: `demo-user-${i % 3}`, path: "/login" }, i));
      break;
    case "credential_stuffing":
      for (let i = 0; i < Math.min(count, 15); i++)
        events.push(mk("failed_login", 3, { userId: `victim-${i}`, path: "/api/auth/token" }, i));
      break;
    case "endpoint_probe":
      for (let i = 0; i < Math.min(count, 8); i++)
        events.push(mk("endpoint_probe", 2, { path: ["/admin", "/wp-admin", "/.env", "/phpmyadmin", "/admin/config", "/admin/users", "/api/v1/admin", "/server-status"][i % 8] }, i));
      break;
    case "excessive_api":
      for (let i = 0; i < Math.min(count, 50); i++)
        events.push(mk("rate_limit_hit", 1, { path: "/api/v1/data", userId: "demo-api-client" }, i));
      break;
    case "malformed":
      for (let i = 0; i < Math.min(count, 12); i++)
        events.push(mk("malformed_request", 1, { path: "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" }, i));
      break;
    case "session_anomaly":
      events.push(mk("failed_login", 2, { userId: "demo-admin", path: "/login" }, 3));
      events.push(mk("failed_login", 2, { userId: "demo-admin", path: "/login" }, 2));
      events.push(mk("session_anomaly", 3, { userId: "demo-admin", sessionId: randomBytes(8).toString("hex"), path: "/account/settings" }, 0));
      break;
    default:
      for (let i = 0; i < count; i++)
        events.push(mk("failed_login", 1, { userId: "demo", path: "/login" }, i));
  }
  return events;
}

export const DEMO_SCENARIOS = [
  { id: "brute_force", label: "Repeated failed logins" },
  { id: "credential_stuffing", label: "Credential stuffing pattern" },
  { id: "endpoint_probe", label: "Suspicious endpoint discovery" },
  { id: "excessive_api", label: "Excessive API requests" },
  { id: "malformed", label: "Malformed requests" },
  { id: "session_anomaly", label: "Unusual session behaviour" },
];
