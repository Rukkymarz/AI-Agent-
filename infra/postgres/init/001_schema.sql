-- AICOMPANY-OS schema. Applied by aicos_migrator; the API connects as aicos_app (DML only).
\connect aicos
SET ROLE aicos_migrator;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------- tenancy & identity
CREATE TABLE tenants (
  id          text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  name        text NOT NULL,
  plan        text NOT NULL DEFAULT 'self-hosted',
  created_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO tenants (id, name) VALUES ('default', 'Default');

-- Users live in Keycloak; this is a projection for joins/reporting (no credentials stored here).
CREATE TABLE users (
  id          text PRIMARY KEY,                     -- Keycloak sub
  tenant_id   text NOT NULL REFERENCES tenants(id),
  username    text NOT NULL,
  email       text,
  roles       text[] NOT NULL DEFAULT '{}',
  disabled    boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, username)
);

-- ---------------------------------------------------------------- agents & plugins
CREATE TABLE agents (
  id          text NOT NULL,
  tenant_id   text NOT NULL REFERENCES tenants(id),
  department  text NOT NULL,
  spec        jsonb NOT NULL,
  source      text NOT NULL DEFAULT 'core',         -- core | plugin:<name>
  enabled     boolean NOT NULL DEFAULT true,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE plugins (
  name            text NOT NULL,
  tenant_id       text NOT NULL REFERENCES tenants(id),
  version         text NOT NULL,
  state           text NOT NULL,
  tier            text NOT NULL CHECK (tier IN ('core','verified','community')),
  manifest        jsonb NOT NULL,
  approved_digest text,
  proposal_id     text,
  granted         text[] NOT NULL DEFAULT '{}',
  history         jsonb NOT NULL DEFAULT '[]',
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, name)
);

-- ---------------------------------------------------------------- tasks
CREATE TABLE tasks (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES tenants(id),
  principal_id    text NOT NULL,
  agent_id        text,
  objective       text NOT NULL,
  status          text NOT NULL,
  result          jsonb,
  project_id      text,
  conversation_id text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  completed_at    timestamptz
);
CREATE INDEX tasks_tenant_created ON tasks (tenant_id, created_at DESC);

-- ---------------------------------------------------------------- approvals
CREATE TABLE approval_proposals (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL REFERENCES tenants(id),
  status      text NOT NULL,
  risk        text NOT NULL,
  body        jsonb NOT NULL,                       -- full Proposal incl. votes & payload hash
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX approvals_queue ON approval_proposals (tenant_id, status, created_at DESC);

-- ---------------------------------------------------------------- memory / knowledge (pgvector)
CREATE TABLE memory_records (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL REFERENCES tenants(id),
  scope       text NOT NULL CHECK (scope IN ('short_term','conversation','agent','project','company','long_term')),
  owner_id    text NOT NULL,
  content     text NOT NULL,
  embedding   vector(1024) NOT NULL,                -- bge-m3; change with AICOS_EMBEDDING_DIM
  metadata    jsonb NOT NULL DEFAULT '{}',
  importance  real NOT NULL DEFAULT 0.5,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz
);
CREATE INDEX memory_scope ON memory_records (tenant_id, scope, owner_id);
CREATE INDEX memory_expiry ON memory_records (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX memory_hnsw ON memory_records USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
CREATE INDEX memory_meta ON memory_records USING gin (metadata jsonb_path_ops);

CREATE TABLE knowledge_documents (
  id           text PRIMARY KEY,
  tenant_id    text NOT NULL REFERENCES tenants(id),
  source       text NOT NULL,
  mime         text NOT NULL,
  content_hash text NOT NULL,
  pii          text[] NOT NULL DEFAULT '{}',
  quarantined  integer NOT NULL DEFAULT 0,
  ingested_by  text NOT NULL,
  ingested_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, content_hash)
);

-- ---------------------------------------------------------------- events (outbox for reliable publish)
CREATE TABLE event_outbox (
  id           text PRIMARY KEY,
  tenant_id    text NOT NULL,
  type         text NOT NULL,
  payload      jsonb NOT NULL,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);
CREATE INDEX outbox_unpublished ON event_outbox (occurred_at) WHERE published_at IS NULL;

-- ---------------------------------------------------------------- immutable audit trail
CREATE TABLE audit_log (
  seq            bigint PRIMARY KEY,
  ts             timestamptz NOT NULL,
  tenant_id      text NOT NULL,
  actor_id       text NOT NULL,
  actor_type     text NOT NULL,
  action         text NOT NULL,
  resource       text NOT NULL,
  outcome        text NOT NULL,
  details        jsonb NOT NULL DEFAULT '{}',
  correlation_id text,
  prev_hash      char(64) NOT NULL,
  hash           char(64) NOT NULL UNIQUE
);
CREATE INDEX audit_tenant_ts ON audit_log (tenant_id, ts DESC);

CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_log is append-only (% blocked)', TG_OP; END $$;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- ---------------------------------------------------------------- row-level security (defence in depth)
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['users','agents','plugins','tasks','approval_proposals','memory_records','knowledge_documents'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (tenant_id = coalesce(current_setting('app.tenant_id', true), tenant_id))$p$, t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------- least-privilege grants
GRANT USAGE ON SCHEMA public TO aicos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, agents, plugins, tasks, approval_proposals, memory_records,
  knowledge_documents, event_outbox TO aicos_app;
GRANT SELECT ON tenants TO aicos_app;
GRANT SELECT, INSERT ON audit_log TO aicos_app;          -- no UPDATE/DELETE, ever
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM aicos_app;
