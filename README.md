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
| DB | Supabase Postgres via Prisma (schema in `supabase/schema.sql`) |
| AI | Provider-independent interface; OpenAI-compatible provider + built-in heuristic fallback |
| Auth | Supabase Auth (email + password); the API validates the bearer access token |

## Quick start

Requires **Node.js >= 20**.

1. In your Supabase project, open **SQL Editor**, paste `supabase/schema.sql` and run it (creates
   all tables and locks them down with RLS; safe to re-run).
2. In **Authentication -> Providers -> Email**, turn off "Confirm email" for local testing
   (otherwise new accounts must click an emailed link before signing in).
3. Create `.env` and put your database password in `DATABASE_URL`
   (**Connect -> Session pooler** string):

```bash
npm install
cp .env.example .env     # then edit DATABASE_URL
npm run db:generate      # builds the Prisma client
npm run dev              # API :4000 + web :5173
```

Do not run `npm run db:push` against Supabase: `supabase/schema.sql` is the source of truth.

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
| `APP_SECRET` | Dev credential-key derivation (set a long random value) |
| `CREDENTIAL_KEY` | Base64 32-byte key for AES-256-GCM credential encryption (prod: set explicitly) |
| `AI_PROVIDER` | `heuristic` (default, zero-config) or `openai` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` | LLM provider settings |
| `DRY_RUN` | `true` makes defensive adapters report what they *would* do without touching production |
| `DATABASE_URL` | Supabase Postgres connection string (Session pooler) |
| `SUPABASE_URL` / `SUPABASE_ANON_KEY` | Supabase project URL + public anon key (server validates tokens with them) |
| `VITE_SUPABASE_URL` / `VITE_SUPABASE_ANON_KEY` | Same values, exposed to the web app |

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
| GET | `/api/auth/me` | current user (sign-up/sign-in/out are handled by Supabase Auth in the browser) |
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
- The API caches a validated access token for 30 s, so a revoked session can stay valid that long.
