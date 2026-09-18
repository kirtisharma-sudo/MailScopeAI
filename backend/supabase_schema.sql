-- MailScope AI — Supabase schema (SIH26106)
-- Stores structured findings only. Raw email bodies are NEVER written here.

create extension if not exists "pgcrypto";

create table if not exists cases (
  id text primary key,                       -- e.g. CASE-AB12CD34EF56
  created_at timestamptz not null default now(),
  classification text not null,              -- benign | suspicious | phishing | impersonation | fraud | malware
  risk_score int not null check (risk_score between 0 and 100),
  confidence int not null check (confidence between 0 and 100),
  source text not null,                      -- pasted_text | eml_upload
  analysis_version text not null,
  analyst_notes text default ''               -- plain text only; sanitized server-side before storage
);

create table if not exists email_headers (
  case_id text primary key references cases(id) on delete cascade,
  from_address text,
  reply_to text,
  return_path text,
  message_id text,
  subject text,
  received_headers jsonb,
  authentication_results jsonb
);

create table if not exists urls (
  id uuid primary key default gen_random_uuid(),
  case_id text references cases(id) on delete cascade,
  url text not null,
  domain text,
  risk_score int,
  indicators jsonb
);

create table if not exists indicators (
  id uuid primary key default gen_random_uuid(),
  case_id text references cases(id) on delete cascade,
  type text not null,                        -- domain | url | url_domain | ip | sender_address | reply_to_domain | return_path_domain | message_id
  value text not null
);

create table if not exists infrastructure (
  id uuid primary key default gen_random_uuid(),
  case_id text references cases(id) on delete cascade,
  ip text not null,
  asn text,
  isp text,
  country text,
  region text,
  city text,
  hosting text,
  vpn_proxy_tor text
);

create table if not exists evidence (
  id uuid primary key default gen_random_uuid(),
  case_id text references cases(id) on delete cascade,
  sha256 text not null,
  evidence_type text not null,               -- pasted_text | eml_upload
  timestamp timestamptz not null,
  description text
);

create table if not exists campaigns (
  id text primary key,                       -- e.g. CAMP-EXAMPLE-COM
  created_at timestamptz not null default now(),
  shared_indicators jsonb,
  status text default 'possible_campaign'
);

create table if not exists campaign_members (
  campaign_id text references campaigns(id) on delete cascade,
  case_id text references cases(id) on delete cascade,
  primary key (campaign_id, case_id)
);

create table if not exists model_versions (
  id uuid primary key default gen_random_uuid(),
  name text not null,                        -- e.g. deberta-phishing
  version text not null,
  trained_at timestamptz,
  dataset_description text,
  eval_accuracy numeric,                     -- NULL until actually measured — never fabricated
  eval_precision numeric,
  eval_recall numeric,
  eval_f1 numeric,
  notes text
);

-- ---------------------------------------------------------------------
-- Row Level Security: lock everything down by default. The backend uses
-- the SERVICE ROLE key (bypasses RLS) — the anon/public key gets NO direct
-- table access. Add narrower policies here only if you build a
-- user-facing read path later (e.g. "users can read their own cases").
-- ---------------------------------------------------------------------
alter table cases enable row level security;
alter table email_headers enable row level security;
alter table urls enable row level security;
alter table indicators enable row level security;
alter table infrastructure enable row level security;
alter table evidence enable row level security;
alter table campaigns enable row level security;
alter table campaign_members enable row level security;
alter table model_versions enable row level security;

-- No policies are created here on purpose: with RLS enabled and zero
-- policies, only the service-role key (used server-side by this backend)
-- can read/write. The anon key used by any future browser-side Supabase
-- call would be denied by default, which is the safe starting point.
