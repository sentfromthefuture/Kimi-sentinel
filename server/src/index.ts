import express from "express";
import cookieParser from "cookie-parser";
import { config } from "./config.js";
import { authRouter } from "./routes/auth.js";
import { websitesRouter } from "./routes/websites.js";
import { eventsRouter, ingestRouter } from "./routes/events.js";
import { incidentsRouter } from "./routes/incidents.js";
import { integrationsRouter } from "./routes/integrations.js";
import { actionsRouter } from "./routes/actions.js";
import { reportsRouter, notificationsRouter } from "./routes/reports.js";
import { rateLimit } from "./middleware/rateLimit.js";
import { startWorker } from "./worker.js";

const app = express();
app.use(express.json({ limit: "256kb" }));
app.use(cookieParser());

// CSRF mitigation: bearer-token auth (no cookies) + JSON-only API + custom header on mutations.
app.use((req, res, next) => {
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method) && !req.path.startsWith("/ingest") && req.headers["x-requested-with"] !== "sentinel")
    return res.status(403).json({ error: "Missing CSRF header" });
  next();
});

app.use("/api", rateLimit({ windowMs: 60_000, max: 300, key: (r) => r.ip ?? "anon" }));
app.use("/api/auth", authRouter);
app.use("/api", websitesRouter);
app.use("/api", eventsRouter);
app.use("/ingest", ingestRouter);       // public ingestion API (key-authenticated)
app.use("/api", incidentsRouter);
app.use("/api", integrationsRouter);
app.use("/api", actionsRouter);
app.use("/api", reportsRouter);
app.use("/api/notifications", notificationsRouter);
app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.use((err: any, _req: any, res: any, _next: any) => {
  console.error(err);
  res.status(500).json({ error: "Internal error" }); // never leak internals
});

app.listen(config.port, () => {
  console.log(`Sentinel AI server on :${config.port}`);
  startWorker();
});
