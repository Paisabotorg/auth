import { verifyAccessToken } from '../lib/jwt.js'
import { query } from '../lib/db.js'

/**
 * Verifies pb_token cookie, attaches req.user. Blocks with 401 if missing/invalid.
 */
export async function requireAuth(req, res, next) {
  const token = req.cookies?.pb_token
  if (!token) return res.status(401).json({ error: 'Unauthorised' })

  const payload = verifyAccessToken(token)
  if (!payload) return res.status(401).json({ error: 'Unauthorised' })

  try {
    const { rows } = await query(
      'SELECT id, email, name, avatar FROM users WHERE id = $1',
      [payload.sub]
    )
    if (!rows.length) return res.status(401).json({ error: 'Unauthorised' })
    req.user = rows[0]
    next()
  } catch (err) {
    next(err)
  }
}

/**
 * Attaches req.user if logged in, but does NOT block unauthenticated requests.
 */
export async function optionalAuth(req, res, next) {
  try {
    const token = req.cookies?.pb_token
    if (!token) { req.user = null; return next() }

    const payload = verifyAccessToken(token)
    if (!payload) { req.user = null; return next() }

    const { rows } = await query(
      'SELECT id, email, name, avatar FROM users WHERE id = $1',
      [payload.sub]
    )
    req.user = rows[0] || null
    next()
  } catch {
    req.user = null
    next()
  }
}
