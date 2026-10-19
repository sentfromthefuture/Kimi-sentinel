-- Sentinel AI -- Supabase schema
-- Run once in: Supabase dashboard -> SQL Editor -> New query -> paste -> Run.
-- Safe to re-run (everything is "if not exists").
--
-- Auth: users live in Supabase Auth (auth.users). userId columns reference it, so
-- deleting a user deletes all of their websites, events, incidents and notifications.
--
-- Access model: ONLY the Sentinel server touches these tables, through a direct Postgres
-- connection (DATABASE_URL, role "postgres", which bypasses RLS). Row Level Security is enabled
-- with no policies and the public API roles are revoked, so the anon key shipped in the browser
-- cannot read or write any of these tables through Supabase's REST API. This matters:
-- "Integration"."credentialsEnc" must never reach a browser.

-- ---------------------------------------------------------------- tables

create table if not exists "Website" (
  "id"              text primary key,
  "userId"          uuid not null references auth.users(id) on delete cascade,
  "url"             text not null,
  "hostname"        text not null,
  "name"            text not null,
  "status"          text not null default 'UNVERIFIED',   -- UNVERIFIED | ACTIVE | SUSPENDED
  "protectionLevel" text not null default 'WATCH',        -- WATCH | MONITOR | GUARDIAN
  "operatingMode"   text not null default 'OBSERVER',     -- OBSERVER | GUARDIAN | INCIDENT_RESPONSE
  "emergencyStop"   boolean not null default false,
  "lastMonitoredAt" timestamptz(3),
  "createdAt"       timestamptz(3) not null default now()
);

create table if not exists "Verification" (
  "id"         text primary key,
  "websiteId"  text not null,
  "method"     text not null,                             -- DNS_TXT | FILE | OAUTH
  "token"      text not null,
  "status"     text not null default 'PENDING',           -- PENDING | VERIFIED | FAILED
  "verifiedAt" timestamptz(3),
  "createdAt"  timestamptz(3) not null default now(),
  constraint "Verification_websiteId_fkey" foreign key ("websiteId")
    references "Website"("id") on delete cascade on update cascade
);

create table if not exists "Integration" (
  "id"              text primary key,
  "websiteId"       text not null,
  "kind"            text not null,                        -- PUBLIC_MONITOR | CLOUDFLARE | WAZUH | CROWDSEC | MODSECURITY | SURICATA | APP_EVENTS
  "status"          text not null default 'DISCONNECTED', -- CONNECTED | DISCONNECTED | ERROR | MISSING_PERMISSIONS
  "credentialsEnc"  text,                                 -- AES-256-GCM encrypted, never exposed to the browser
  "scopes"          text not null default '[]',           -- JSON array of granted scopes
  "lastHealthCheck" timestamptz(3),
  "lastError"       text,
  "createdAt"       timestamptz(3) not null default now(),
  constraint "Integration_websiteId_fkey" foreign key ("websiteId")
    references "Website"("id") on delete cascade on update cascade
);

create table if not exists "SecurityEvent" (
  "id"            text primary key,
  "websiteId"     text not null,
  "integrationId" text,
  "source"        text not null,                          -- REAL | SIMULATED | TEST
  "type"          text not null,
  "severity"      integer not null,                       -- 0 info, 1 low, 2 medium, 3 high, 4 critical
  "sourceIp"      text,
  "payload"       text not null,                          -- JSON: normalized event fields
  "fingerprint"   text not null,                          -- dedupe key
  "receivedAt"    timestamptz(3) not null default now(),
  constraint "SecurityEvent_websiteId_fkey" foreign key ("websiteId")
    references "Website"("id") on delete cascade on update cascade,
  constraint "SecurityEvent_integrationId_fkey" foreign key ("integrationId")
    references "Integration"("id") on delete set null on update cascade
);

create table if not exists "Incident" (
  "id"         text primary key,
  "websiteId"  text not null,
  "title"      text not null,
  "severity"   integer not null,
  "status"     text not null default 'NEW',               -- NEW | INVESTIGATING | CONTAINED | AWAITING_APPROVAL | RESOLVED | FALSE_POSITIVE
  "startedAt"  timestamptz(3) not null default now(),
  "resolvedAt" timestamptz(3),
  constraint "Incident_websiteId_fkey" foreign key ("websiteId")
    references "Website"("id") on delete cascade on update cascade
);

-- Many-to-many join table Prisma expects for Incident.events <-> SecurityEvent.incidents
-- (A = Incident.id, B = SecurityEvent.id).
create table if not exists "_IncidentEvents" (
  "A" text not null references "Incident"("id") on delete cascade on update cascade,
  "B" text not null references "SecurityEvent"("id") on delete cascade on update cascade,
  constraint "_IncidentEvents_AB_pkey" primary key ("A", "B")
);

create table if not exists "Investigation" (
  "id"                text primary key,
  "incidentId"        text not null,
  "eventId"           text,
  "status"            text not null default 'NEW',        -- NEW | INVESTIGATING | COMPLETE | ERROR
  "aiProvider"        text not null,
  "explanation"       text not null,
  "classification"    text not null,                      -- benign | suspicious | confirmed_threat
  "confidence"        double precision not null,
  "recommendedAction" text,
  "evidence"          text not null,                      -- JSON
  "actionRequest"     text,                               -- JSON: schema-validated action request
  "createdAt"         timestamptz(3) not null default now(),
  constraint "Investigation_incidentId_fkey" foreign key ("incidentId")
    references "Incident"("id") on delete cascade on update cascade,
  constraint "Investigation_eventId_fkey" foreign key ("eventId")
    references "SecurityEvent"("id") on delete set null on update cascade
);

create table if not exists "DefensiveAction" (
  "id"            text primary key,
  "incidentId"    text,
  "integrationId" text,
  "websiteId"     text not null,
  "type"          text not null,                          -- rate_limit | block_ip | revoke_session | challenge | notify
  "params"        text not null,                          -- JSON
  "reason"        text not null,
  "evidence"      text not null,                          -- JSON
  "status"        text not null default 'REQUESTED',      -- REQUESTED | REJECTED_POLICY | APPROVAL_REQUIRED | APPROVED | EXECUTED | CONFIRMED | FAILED | EXPIRED | ROLLED_BACK
  "result"        text,
  "error"         text,
  "requestedBy"   text not null,                          -- agent | user
  "approvedBy"    text,
  "expiresAt"     timestamptz(3),
  "executedAt"    timestamptz(3),
  "createdAt"     timestamptz(3) not null default now(),
  constraint "DefensiveAction_incidentId_fkey" foreign key ("incidentId")
    references "Incident"("id") on delete set null on update cascade,
  constraint "DefensiveAction_integrationId_fkey" foreign key ("integrationId")
    references "Integration"("id") on delete set null on update cascade
);

create table if not exists "ApprovalRequest" (
  "id"        text primary key,
  "actionId"  text not null unique,
  "status"    text not null default 'PENDING',            -- PENDING | APPROVED | DENIED
  "decidedBy" text,
  "createdAt" timestamptz(3) not null default now(),
  "decidedAt" timestamptz(3),
  constraint "ApprovalRequest_actionId_fkey" foreign key ("actionId")
    references "DefensiveAction"("id") on delete cascade on update cascade
);

create table if not exists "AuditLog" (
  "id"        text primary key,
  "userId"    text,
  "actor"     text not null,                              -- user:<id> | agent | system
  "action"    text not null,
  "target"    text not null,
  "meta"      text not null,                              -- JSON
  "createdAt" timestamptz(3) not null default now()
);

create table if not exists "AgentDecision" (
  "id"        text primary key,
  "websiteId" text not null,
  "mode"      text not null,
  "decision"  text not null,                              -- JSON
  "createdAt" timestamptz(3) not null default now()
);

create table if not exists "Notification" (
  "id"        text primary key,
  "userId"    uuid not null references auth.users(id) on delete cascade,
  "level"     text not null,                              -- info | warning | critical
  "message"   text not null,
  "read"      boolean not null default false,
  "createdAt" timestamptz(3) not null default now()
);

-- ---------------------------------------------------------------- indexes

create index if not exists "Website_userId_idx"                 on "Website"("userId");
create index if not exists "SecurityEvent_websiteId_receivedAt_idx" on "SecurityEvent"("websiteId", "receivedAt");
create index if not exists "SecurityEvent_fingerprint_idx"      on "SecurityEvent"("fingerprint");
create index if not exists "_IncidentEvents_B_index"            on "_IncidentEvents"("B");
create index if not exists "AuditLog_createdAt_idx"             on "AuditLog"("createdAt");
create index if not exists "AgentDecision_websiteId_createdAt_idx" on "AgentDecision"("websiteId", "createdAt");
create index if not exists "Notification_userId_read_idx"       on "Notification"("userId", "read");

-- ---------------------------------------------------------------- lock down the REST API

alter table "Website"          enable row level security;
alter table "Verification"     enable row level security;
alter table "Integration"      enable row level security;
alter table "SecurityEvent"    enable row level security;
alter table "Incident"         enable row level security;
alter table "_IncidentEvents"  enable row level security;
alter table "Investigation"    enable row level security;
alter table "DefensiveAction"  enable row level security;
alter table "ApprovalRequest"  enable row level security;
alter table "AuditLog"         enable row level security;
alter table "AgentDecision"    enable row level security;
alter table "Notification"     enable row level security;

revoke all on "Website", "Verification", "Integration", "SecurityEvent", "Incident",
              "_IncidentEvents", "Investigation", "DefensiveAction", "ApprovalRequest",
              "AuditLog", "AgentDecision", "Notification"
  from anon, authenticated;
