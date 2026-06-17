-- Migration 001: paisabot_auth schema
-- Run once on the VPS Postgres instance (paisabot_cms database)
-- psql -U paisabot_cms -d paisabot_cms -f migrations/001_auth_schema.sql

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE SCHEMA IF NOT EXISTS paisabot_auth;

CREATE TABLE IF NOT EXISTS paisabot_auth.users (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  email         CITEXT      UNIQUE,                         -- null for guests
  name          TEXT,
  picture_url   TEXT,
  lang          VARCHAR(5),                                 -- null until onboarding
  role          VARCHAR(20) NOT NULL DEFAULT 'user',        -- 'user' | 'guest'
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ,
  status        VARCHAR(20) NOT NULL DEFAULT 'active'       -- 'active' | 'disabled'
);

CREATE TABLE IF NOT EXISTS paisabot_auth.oauth_identities (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL REFERENCES paisabot_auth.users(id) ON DELETE CASCADE,
  provider     VARCHAR(50) NOT NULL DEFAULT 'google',
  provider_sub TEXT        NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, provider_sub)
);

CREATE TABLE IF NOT EXISTS paisabot_auth.sessions (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID        NOT NULL REFERENCES paisabot_auth.users(id) ON DELETE CASCADE,
  refresh_token_hash TEXT        NOT NULL UNIQUE,
  user_agent         TEXT,
  ip                 INET,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at         TIMESTAMPTZ NOT NULL,
  revoked_at         TIMESTAMPTZ,
  rotated_from       UUID        REFERENCES paisabot_auth.sessions(id)
);

CREATE INDEX IF NOT EXISTS ix_sessions_user_id   ON paisabot_auth.sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires_at ON paisabot_auth.sessions(expires_at);
