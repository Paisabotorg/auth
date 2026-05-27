import { createServerClient } from '@supabase/ssr'
import { createClient } from '@supabase/supabase-js'
import config from '../config.js'

/**
 * Per-request Supabase client (anon key) — reads/writes cookies via req/res.
 * Used for OAuth flows and session exchange.
 */
export function createRequestClient(req, res) {
  return createServerClient(config.supabase.url, config.supabase.anonKey, {
    cookies: {
      getAll() {
        return Object.entries(req.cookies || {}).map(([name, value]) => ({
          name,
          value,
        }))
      },
      setAll(cookiesToSet) {
        cookiesToSet.forEach(({ name, value, options }) => {
          res.cookie(name, value, {
            ...options,
            domain: config.cookie.domain,
            secure: config.cookie.secure,
            sameSite: 'lax',
          })
        })
      },
    },
  })
}

/**
 * Service-role client — bypasses RLS, use only server-side for admin ops.
 */
export const adminClient = createClient(
  config.supabase.url,
  config.supabase.serviceRoleKey,
  { auth: { autoRefreshToken: false, persistSession: false } }
)
