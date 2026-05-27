import { createRequestClient } from '../lib/supabase.js'

/**
 * Express middleware — verifies Supabase session from cookies.
 * On success attaches req.user and req.session.
 * On failure returns 401.
 */
export async function requireAuth(req, res, next) {
  try {
    const supabase = createRequestClient(req, res)
    const { data: { user }, error } = await supabase.auth.getUser()

    if (error || !user) {
      return res.status(401).json({ error: 'Unauthorised' })
    }

    req.user = user
    next()
  } catch (err) {
    next(err)
  }
}

/**
 * Middleware — attaches user to req if logged in, but does NOT block unauthenticated requests.
 * Useful for endpoints that behave differently for logged-in vs. anonymous users.
 */
export async function optionalAuth(req, res, next) {
  try {
    const supabase = createRequestClient(req, res)
    const { data: { user } } = await supabase.auth.getUser()
    req.user = user || null
    next()
  } catch {
    req.user = null
    next()
  }
}
