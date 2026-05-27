import { createServerClient } from '@supabase/ssr'
import { createClient } from '@supabase/supabase-js'
import { createRequire } from 'module'
import config from '../config.js'

const require = createRequire(import.meta.url)
const ws = require('ws')

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
  {
    auth: { autoRefreshToken: false, persistSession: false },
    realtime: { transport: ws },
  }
)
