-- RevenueOS schema. Tenant isolation via RLS (same pattern as 001_schema.sql).
\connect aicos
SET ROLE aicos_migrator;

CREATE TYPE lead_grade AS ENUM ('platinum','gold','silver','bronze','ignore');

CREATE TABLE leads (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           text NOT NULL REFERENCES tenants(id),
  business_name       text NOT NULL,
  owner_name          text,
  industry            text,
  sub_industry        text,
  website             text,
  google_business_url text,
  linkedin_url        text,
  facebook_url        text,
  instagram_url       text,
  phone               text,
  email               text,
  city                text,
  state               text,
  zip_code            text,
  timezone            text NOT NULL DEFAULT 'America/New_York',
  employee_count      integer CHECK (employee_count >= 0),
  estimated_revenue   numeric(14,2) CHECK (estimated_revenue >= 0),
  years_in_business   integer CHECK (years_in_business >= 0),
  lead_source         text NOT NULL DEFAULT 'manual',
  score               smallint NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
  grade               lead_grade NOT NULL DEFAULT 'ignore',
  status              text NOT NULL DEFAULT 'new',
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX leads_dedupe_web ON leads (tenant_id, lower(regexp_replace(website, '^https?://(www\.)?', ''))) WHERE website IS NOT NULL;
CREATE INDEX leads_score ON leads (tenant_id, score DESC);
CREATE INDEX leads_status ON leads (tenant_id, status);

CREATE TABLE seo_analysis (
  lead_id            uuid PRIMARY KEY REFERENCES leads(id) ON DELETE CASCADE,
  domain_authority   smallint,
  page_speed_score   smallint,
  mobile_score       smallint,
  indexed_pages      integer,
  backlinks          integer,
  keyword_count      integer,
  organic_visibility numeric(5,2),
  local_seo_score    smallint,
  seo_score          smallint NOT NULL DEFAULT 0,
  analyzed_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE reputation (
  lead_id          uuid PRIMARY KEY REFERENCES leads(id) ON DELETE CASCADE,
  google_rating    numeric(2,1),
  google_reviews   integer NOT NULL DEFAULT 0,
  facebook_rating  numeric(2,1),
  total_reviews    integer NOT NULL DEFAULT 0,
  sentiment_score  numeric(4,3),
  response_rate    numeric(4,3),
  reputation_score smallint NOT NULL DEFAULT 0
);

CREATE TABLE opportunity (
  lead_id              uuid PRIMARY KEY REFERENCES leads(id) ON DELETE CASCADE,
  poor_seo             boolean NOT NULL DEFAULT false,
  slow_website         boolean NOT NULL DEFAULT false,
  outdated_design      boolean NOT NULL DEFAULT false,
  missing_chat         boolean NOT NULL DEFAULT false,
  low_reviews          boolean NOT NULL DEFAULT false,
  weak_content         boolean NOT NULL DEFAULT false,
  weak_social_presence boolean NOT NULL DEFAULT false,
  no_retargeting       boolean NOT NULL DEFAULT false,
  opportunity_score    smallint NOT NULL DEFAULT 0,
  notes                text[] NOT NULL DEFAULT '{}',
  business_health      smallint,
  analysis             jsonb                                   -- full BusinessAnalysis incl. findings
);

CREATE TABLE campaigns (
  id                     uuid PRIMARY KEY,
  tenant_id              text NOT NULL REFERENCES tenants(id),
  name                   text NOT NULL,
  sequence               text NOT NULL,
  brand                  jsonb NOT NULL,
  consultant             text NOT NULL,
  status                 text NOT NULL,
  proposal_id            text REFERENCES approval_proposals(id),
  approved_template_hash char(64),
  approved_lead_hash     char(64),
  created_by             text NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now()
);

-- `outreach` = one row per lead per sequence (spec columns + engine state)
CREATE TABLE outreach (
  id              uuid PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES tenants(id),
  campaign_id     uuid NOT NULL REFERENCES campaigns(id),
  lead_id         uuid NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
  sequence_name   text NOT NULL,
  email_sent      boolean NOT NULL DEFAULT false,
  opened          boolean NOT NULL DEFAULT false,
  clicked         boolean NOT NULL DEFAULT false,
  replied         boolean NOT NULL DEFAULT false,
  meeting_booked  boolean NOT NULL DEFAULT false,
  proposal_sent   boolean NOT NULL DEFAULT false,
  client_signed   boolean NOT NULL DEFAULT false,
  last_contact    timestamptz,
  status          text NOT NULL DEFAULT 'active',
  started_at      timestamptz NOT NULL,
  UNIQUE (campaign_id, lead_id)
);
CREATE INDEX outreach_active ON outreach (tenant_id, status) WHERE status = 'active';

CREATE TABLE outreach_messages (
  message_id    text PRIMARY KEY,
  outreach_id   uuid NOT NULL REFERENCES outreach(id) ON DELETE CASCADE,
  step          text NOT NULL,
  sent_at       timestamptz NOT NULL,
  template_hash char(64) NOT NULL
);

CREATE TABLE email_events (
  id          bigserial PRIMARY KEY,
  outreach_id uuid REFERENCES outreach(id) ON DELETE CASCADE,
  message_id  text,
  event       text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

-- hashed so suppression survives GDPR erasure of the lead row
CREATE TABLE email_suppression (
  tenant_id   text NOT NULL REFERENCES tenants(id),
  email_hash  char(64) NOT NULL,
  reason      text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, email_hash)
);

CREATE TABLE deals (
  id               uuid PRIMARY KEY,
  tenant_id        text NOT NULL REFERENCES tenants(id),
  lead_id          uuid NOT NULL REFERENCES leads(id),
  stage            text NOT NULL,
  package          text,
  monthly_value    numeric(12,2) NOT NULL DEFAULT 0,
  setup_fee        numeric(12,2) NOT NULL DEFAULT 0,
  contract_months  smallint NOT NULL DEFAULT 12,
  campaign_id      uuid REFERENCES campaigns(id),
  contract_proposal_id text REFERENCES approval_proposals(id),
  proposal_sent_at timestamptz,
  won_at           timestamptz,
  lost_reason      text,
  churned_at       timestamptz,
  history          jsonb NOT NULL DEFAULT '[]',
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT won_needs_contract CHECK (stage <> 'won' OR contract_proposal_id IS NOT NULL),
  CONSTRAINT won_needs_mrr CHECK (stage <> 'won' OR monthly_value > 0)
);

-- BI views
CREATE VIEW revenue_mrr AS
  SELECT tenant_id, sum(monthly_value) AS mrr, sum(monthly_value) * 12 AS arr, count(*) AS clients
  FROM deals WHERE stage = 'won' GROUP BY tenant_id;
CREATE VIEW revenue_funnel AS
  SELECT o.tenant_id, o.campaign_id, count(*) AS enrolled,
         avg(o.opened::int) AS open_rate, avg(o.clicked::int) AS click_rate,
         avg(o.replied::int) AS reply_rate, avg(o.meeting_booked::int) AS meeting_rate
  FROM outreach o GROUP BY o.tenant_id, o.campaign_id;

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['leads','campaigns','outreach','email_suppression','deals'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (tenant_id = coalesce(current_setting('app.tenant_id', true), tenant_id))$p$, t);
  END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON leads, seo_analysis, reputation, opportunity, campaigns, outreach,
  outreach_messages, deals TO aicos_app;
GRANT SELECT, INSERT ON email_events, email_suppression TO aicos_app;   -- suppression is never deleted by the app
GRANT USAGE ON SEQUENCE email_events_id_seq TO aicos_app;
GRANT SELECT ON revenue_mrr, revenue_funnel TO aicos_app;
