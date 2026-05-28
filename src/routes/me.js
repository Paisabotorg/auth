import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import { query } from '../lib/db.js'

const router = Router()

/**
 * GET /me
 * Returns authenticated user profile + subscription + prefs.
 * Called by frontends with credentials: 'include'.
 */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT
         u.id, u.email, u.name, u.avatar,
         s.tier, s.status AS subscription_status, s.expires_at,
         p.language, p.newsletter, p.stocks, p.indices, p.settings
       FROM users u
       LEFT JOIN subscriptions s ON s.user_id = u.id
       LEFT JOIN user_prefs p ON p.user_id = u.id
       WHERE u.id = $1`,
      [req.user.id]
    )

    const row = rows[0]
    res.json({
      authenticated: true,
      user: {
        id: row.id,
        email: row.email,
        name: row.name,
        avatar: row.avatar,
      },
      subscription: {
        tier: row.tier || 'free',
        status: row.subscription_status || 'active',
        expiresAt: row.expires_at || null,
      },
      prefs: {
        language: row.language || 'en',
        newsletter: row.newsletter || false,
        stocks: row.stocks || [],
        indices: row.indices || [],
        settings: row.settings || {},
      },
    })
  } catch (err) {
    next(err)
  }
})

/**
 * PATCH /me/prefs
 * Update user preferences (language, newsletter, stocks, indices, settings).
 */
router.patch('/prefs', requireAuth, async (req, res, next) => {
  try {
    const { language, newsletter, stocks, indices, settings } = req.body
    const userId = req.user.id

    const updates = []
    const values = [userId]
    let i = 2

    if (language !== undefined) { updates.push(`language = $${i++}`); values.push(language) }
    if (newsletter !== undefined) {
      updates.push(`newsletter = $${i++}`); values.push(newsletter)
      updates.push(`newsletter_at = CASE WHEN $${i++} THEN NOW() ELSE newsletter_at END`); values.push(newsletter)
    }
    if (stocks !== undefined) { updates.push(`stocks = $${i++}`); values.push(stocks) }
    if (indices !== undefined) { updates.push(`indices = $${i++}`); values.push(indices) }
    if (settings !== undefined) { updates.push(`settings = settings || $${i++}`); values.push(JSON.stringify(settings)) }

    if (!updates.length) return res.json({ ok: true })

    updates.push('updated_at = NOW()')

    await query(
      `INSERT INTO user_prefs (user_id) VALUES ($1)
       ON CONFLICT (user_id) DO UPDATE SET ${updates.join(', ')}`,
      values
    )

    res.json({ ok: true })
  } catch (err) {
    next(err)
  }
})

/**
 * GET /me/check — fast unauthenticated cookie check (no DB hit)
 */
router.get('/check', (req, res) => {
  const token = req.cookies?.pb_token
  if (!token) return res.json({ authenticated: false })

  import('../lib/jwt.js').then(({ verifyAccessToken }) => {
    const payload = verifyAccessToken(token)
    if (!payload) return res.json({ authenticated: false })
    res.json({ authenticated: true, userId: payload.sub })
  })
})

export default router
