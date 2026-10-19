# Sentinel AI

**Your Autonomous AI Security Agent.** An AI-powered website security platform that monitors
authorized signals, investigates threats with a language model, and executes **policy-controlled**
defensive actions through verified integrations.

> **Core principle:** the AI investigates and proposes; a separate, deterministic, policy-controlled
> system enforces. A URL initiates onboarding — it grants no permissions by itself.

---

## Features

- **Website onboarding with ownership verification** (DNS TXT or well-known file). Private IPs,
  localhost, link-local, and cloud-metadata destinations are rejected (SSRF guard).
- **Three protection levels** — External Watch (public indicators only), Security Monitor
  (authorized telemetry), Active Guardian (defensive permissions).
- **Three operating modes** — Observer (recommend only), Guardian (auto-execute reversible,
  policy-passing actions), Incident Response (prepared containment, human approval for
  high-impact actions).
- **Autonomous agent pipeline** — ingest -> normalize -> correlate -> deterministic rule
  detection -> AI investigation -> structured action proposal -> policy engine ->
  defensive controller -> outcome verification -> monitoring.
- **Deterministic policy engine** — scope checks, allowlists, rate limits, confidence/severity
  thresholds, approval gates, expiry. Enforced **outside** the AI model; the agent cannot
  modify its own safeguards.
- **Modular integrations** — Cloudflare adapter (real API), app event ingestion API,
  pluggable slots for Wazuh/CrowdSec/ModSecurity/Suricata. Nothing shows CONNECTED until a
  real health check succeeds.
- **Honest telemetry** — REAL / SIMULATED / TEST events are always distinguished. Demo mode
  generates clearly-labelled simulated attacks.
- **Emergency stop, rollback, audit log, tenant isolation, encrypted credentials.**

## Tech stack

| Layer | Choice |
|---|---|
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS |
| Backend | Node.js + Express + TypeScript (ESM) |
| DB | SQLite via Prisma (dev) — Postgres via docker-compose (prod path) |
| AI | Provider-independent interface; OpenAI-compatible provider + built-in heuristic fallback |
| Auth | scrypt password hashing, httpOnly sessions |

## Quick start

Requires **Node.js >= 20**.

```bash
npm install
cp .env.example .env
npm run db:push     # creates server/prisma/dev.db
npm run dev         # API :4000 + web :5173
```

Open http://localhost:5173, register, and walk the demo flow:

1. **Protected Websites** -> add any public URL -> verify ownership (DNS TXT or file method)
2. **Integrations** -> add `PUBLIC_MONITOR` (no creds needed)
3. **Live Activity** -> run a demo scenario (brute force, credential stuffing, ...) — all
   events are labelled SIMULATED
4. Watch **Investigations** — the agent correlates events, fires deterministic rules, the AI
   classifies, and a defensive action is proposed
5. **Agent Settings** -> switch Observer to Guardian, connect a WAF integration to enable
   real (or `DRY_RUN=true` simulated) execution
6. **Active Defenses** -> approve/deny the approval queue, hit EMERGENCY STOP

## Configuration

See `.env.example`. Key variables:

| Variable | Purpose |
|---|---|
| `APP_SECRET` | Session signing / dev credential-key derivation (set a long random value) |
| `CREDENTIAL_KEY` | Base64 32-byte key for AES-256-GCM credential encryption (prod: set explicitly) |
| `AI_PROVIDER` | `heuristic` (default, zero-config) or `openai` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` | LLM provider settings |
| `DRY_RUN` | `true` makes defensive adapters report what they *would* do without touching production |
| `DATABASE_URL` | `file:./dev.db` (SQLite default); use `docker-compose.yml` for Postgres |

## Architecture

```
web/ (React SPA, dark command-centre UI)
server/
  src/
    index.ts            Express app, CSRF header check, global rate limit
    worker.ts           background loop: rule expiry rollback, scheduled monitoring, re-detection
    middleware/         auth, tenant isolation, rate limiting
    lib/                SSRF-safe URL validation, AES-256-GCM crypto, audit log
    services/
      agent.ts          the autonomous pipeline
      detector.ts       deterministic detection rules (R1-R6)
      investigator.ts   AI provider interface (OpenAI + heuristic fallback, schema-validated)
      policyEngine.ts   THE enforcement gate — the AI cannot bypass it
      actionController  executes via adapters, verifies outcomes, expiry sweep
      verification.ts   ownership verification
      baseline.ts       safe public checks (read-only, <=3 requests)
      normalizer.ts     untrusted-payload normalization (prompt-injection hardening)
      threatIntel.ts    pluggable reputation providers (signal, not proof)
      demo.ts           labelled simulated event generator
    integrations/       IntegrationAdapter interface + Cloudflare adapter + registry
    routes/             auth, websites, events (+ /ingest API), incidents, actions,
                        integrations, reports, notifications
  prisma/schema.prisma  all models incl. AuditLog, ApprovalRequest, AgentDecision
```

### The agent decision loop

```
event -> normalize -> dedupe -> store
  -> correlate (10-min window) -> deterministic rules
  -> AI investigate (structured, schema-validated output)
  -> classify (benign / suspicious / confirmed_threat) + recommend action
  -> policy engine (emergency stop? scope? allowlist? rate limit? confidence? severity?
     mode? approval needed?)
  -> defensive controller -> integration adapter -> outcome CONFIRMED/FAILED
  -> record + audit + notify -> keep monitoring
```

### Safety invariants

1. The agent never holds production credentials — only the controller talks to integrations.
2. The policy engine is code, not prompts. It cannot be persuaded, jailbroken, or reconfigured
   by the AI.
3. High-impact actions (`block_ip`, `revoke_session`) always require human approval.
4. All automated actions are temporary, reversible, expiring, and rollback-capable.
5. Events, logs, and threat-intel text are treated as untrusted data (delimited, capped,
   schema-validated).
6. Missing telemetry is reported as failure — never as "all clear".

## API overview (selected)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/register` / `login` / `logout` | account management |
| GET/POST | `/api/websites` | inventory; POST validates URL + blocks unsafe targets |
| POST | `/api/websites/:id/verification` + `.../check` | ownership proof |
| POST | `/api/websites/:id/baseline` | safe public assessment (verified sites only) |
| PATCH | `/api/websites/:id/mode` | user-controlled operating mode |
| POST | `/api/websites/:id/emergency-stop` | pause automated defenses |
| POST | `/api/websites/:id/demo` | labelled simulated scenarios |
| POST | `/ingest/:websiteId/events` | app event ingestion (Bearer ingestion key) |
| GET | `/api/websites/:id/report` | weekly report + recommendations |
| POST | `/api/actions/:id/approve` / `deny` / `rollback` | human gates |

## Testing

```bash
npm test -w server     # SSRF guard, policy engine gates, prompt-injection hardening
```

## Implementation stage map

1. Functional app + demo mode - done
2. Ownership verification + safe public checks - done
3. Event ingestion + rule detection + incidents - done
4. AI investigator (provider-independent) - done
5. Defensive integration (Cloudflare, dry-run capable) - done
6. Controlled autonomy (temporary rules, expiry, rollback, approvals) - done
7. Production hardening - ongoing: add adapter test suites, email/webhook notifications,
   rate-limit provider configs

## Honest limitations

- The Cloudflare adapter is real API code but needs live credentials to exercise end-to-end;
  use `DRY_RUN=true` for safe pipeline testing.
- Wazuh/CrowdSec/ModSecurity/Suricata adapters are specified by the `IntegrationAdapter`
  interface in `server/src/integrations/` — implement against each provider's documented API.
- SQLite is the dev default; switch `DATABASE_URL` to Postgres for production.
