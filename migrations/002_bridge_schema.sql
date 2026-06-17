-- Migration 002: bridge existing public schema to the new auth service design.
-- Idempotent (all ADD COLUMN IF NOT EXISTS / CREATE TABLE IF NOT EXISTS).
--
-- Existing schema:  users(avatar, google_id), sessions(refresh_token plain),
--                   user_prefs(language)
-- New schema adds:  users.picture_url, lang, role, status, last_login_at,
--                   cross_lang_routing; sessions.refresh_token_hash,
--                   revoked_at, rotated_from, last_used_at;
--                   table oauth_identities.

-- ── users ────────────────────────────────────────────────────────────────────

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS picture_url       TEXT,
  ADD COLUMN IF NOT EXISTS lang              VARCHAR(5),
  ADD COLUMN IF NOT EXISTS role              VARCHAR(20) NOT NULL DEFAULT 'user',
  ADD COLUMN IF NOT EXISTS status            VARCHAR(20) NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS last_login_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS cross_lang_routing VARCHAR(10) NOT NULL DEFAULT 'ask';

-- Backfill picture_url from avatar where not yet set
UPDATE public.users SET picture_url = avatar WHERE picture_url IS NULL AND avatar IS NOT NULL;

-- Backfill lang from user_prefs.language
UPDATE public.users u
SET lang = up.language
FROM public.user_prefs up
WHERE up.user_id = u.id AND u.lang IS NULL AND up.language IS NOT NULL;

-- ── oauth_identities ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.oauth_identities (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  provider     VARCHAR(50) NOT NULL DEFAULT 'google',
  provider_sub TEXT        NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, provider_sub)
);

-- Migrate existing google_id rows (idempotent via ON CONFLICT DO NOTHING)
INSERT INTO public.oauth_identities (user_id, provider, provider_sub)
SELECT id, 'google', google_id
FROM public.users
WHERE google_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- ── sessions ─────────────────────────────────────────────────────────────────

-- Make refresh_token nullable (new sessions use refresh_token_hash only)
ALTER TABLE public.sessions ALTER COLUMN refresh_token DROP NOT NULL;

ALTER TABLE public.sessions
  ADD COLUMN IF NOT EXISTS refresh_token_hash TEXT,
  ADD COLUMN IF NOT EXISTS last_used_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS revoked_at         TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS rotated_from       UUID REFERENCES public.sessions(id);

-- Hash existing plain tokens (SHA-256 hex via pgcrypto).
-- This invalidates existing sessions — users will need to log in again.
-- Requires pgcrypto extension.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

UPDATE public.sessions
SET refresh_token_hash = encode(digest(refresh_token, 'sha256'), 'hex')
WHERE refresh_token_hash IS NULL AND refresh_token IS NOT NULL;

-- Add unique constraint on hash if not already present
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'sessions_refresh_token_hash_key'
  ) THEN
    ALTER TABLE public.sessions ADD CONSTRAINT sessions_refresh_token_hash_key UNIQUE (refresh_token_hash);
  END IF;
END$$;

-- ── done ─────────────────────────────────────────────────────────────────────
