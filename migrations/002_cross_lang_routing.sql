-- Migration 002: add cross_lang_routing preference to users
-- Run: psql $DATABASE_URL -f migrations/002_cross_lang_routing.sql

ALTER TABLE paisabot_auth.users
  ADD COLUMN IF NOT EXISTS cross_lang_routing VARCHAR(10) NOT NULL DEFAULT 'ask';

-- Valid values: 'ask' | 'always' | 'never'
-- 'ask'    → show interstitial on cross-language story open (default)
-- 'always' → silently redirect to preferred language variant
-- 'never'  → never prompt, stay on the opened language
