import { verifySessionToken } from '../lib/jwt.js'
import { query } from '../lib/db.js'

export async function requireAuth(req, res, next) {
  const token = req.cookies?.pb_session
  if (!token) return res.status(401).json({ error: 'Unauthorised' })

  const payload = verifySessionToken(token)
  if (!payload) return res.status(401).json({ error: 'Unauthorised' })

  try {
    const { rows } = await query(
      'SELECT id, email, name, picture_url, lang, role FROM users WHERE id = $1 AND status = $2',
      [payload.sub, 'active']
    )
    if (!rows.length) return res.status(401).json({ error: 'Unauthorised' })
    req.user = rows[0]
    next()
  } catch (err) {
    next(err)
  }
}

export async function optionalAuth(req, res, next) {
  try {
    const token = req.cookies?.pb_session
    if (!token) { req.user = null; return next() }
    const payload = verifySessionToken(token)
    if (!payload) { req.user = null; return next() }
    const { rows } = await query(
      'SELECT id, email, name, picture_url, lang, role FROM users WHERE id = $1 AND status = $2',
      [payload.sub, 'active']
    )
    req.user = rows[0] || null
    next()
  } catch {
    req.user = null
    next()
  }
}
