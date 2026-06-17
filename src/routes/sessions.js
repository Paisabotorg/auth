import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import { query } from '../lib/db.js'
import { hashToken } from '../lib/jwt.js'
import config from '../config.js'

const router = Router()

// ── GET /sessions — list active sessions for the current user ─────────────────

router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, user_agent, ip::text AS ip, created_at, last_used_at, expires_at
       FROM sessions
       WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
       ORDER BY last_used_at DESC`,
      [req.user.id]
    )

    // Mark which session is the current one (matched by refresh token)
    const currentHash = req.cookies?.pb_refresh ? hashToken(req.cookies.pb_refresh) : null
    const { rows: currentRows } = currentHash
      ? await query(
          'SELECT id FROM sessions WHERE refresh_token_hash = $1',
          [currentHash]
        )
      : { rows: [] }

    const currentId = currentRows[0]?.id

    res.json(rows.map(s => ({
      id:          s.id,
      user_agent:  s.user_agent,
      ip:          s.ip,
      created_at:  s.created_at,
      last_used_at: s.last_used_at,
      expires_at:  s.expires_at,
      current:     s.id === currentId,
    })))
  } catch (err) {
    next(err)
  }
})

// ── POST /sessions/:id/revoke ─────────────────────────────────────────────────

router.post('/:id/revoke', requireAuth, async (req, res, next) => {
  try {
    const { rowCount } = await query(
      `UPDATE sessions SET revoked_at = NOW()
       WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [req.params.id, req.user.id]
    )
    if (!rowCount) return res.status(404).json({ error: 'Session not found' })
    res.json({ ok: true })
  } catch (err) {
    next(err)
  }
})

export default router
