import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import { signSessionToken, verifySessionToken } from '../lib/jwt.js'
import { query } from '../lib/db.js'
import config, { LANG_SUBDOMAIN } from '../config.js'

const router = Router()
const VALID_LANGS = new Set(Object.keys(LANG_SUBDOMAIN))
const VALID_ROUTING = new Set(['ask', 'always', 'never'])

const SESSION_COOKIE_OPTS = {
  httpOnly: true,
  secure:   config.cookie.secure,
  sameSite: 'lax',
  domain:   config.cookie.domain,
  path:     '/',
  maxAge:   config.jwt.sessionTtlSeconds * 1000,
}

const LANG_COOKIE_OPTS = {
  secure:   config.cookie.secure,
  sameSite: 'lax',
  domain:   config.cookie.domain,
  path:     '/',
  maxAge:   config.jwt.refreshTtlDays * 24 * 60 * 60 * 1000,
}

// ── GET /me ───────────────────────────────────────────────────────────────────

router.get('/', requireAuth, (req, res) => {
  const u = req.user
  res.json({
    sub:               u.id,
    email:             u.email              || null,
    name:              u.name               || null,
    picture:           u.picture_url        || null,
    lang:              u.lang               || null,
    role:              u.role,
    cross_lang_routing: u.cross_lang_routing || 'ask',
  })
})

// ── PATCH /me — update lang (Phase 2 also uses this) ─────────────────────────

router.patch('/', requireAuth, async (req, res, next) => {
  try {
    const { lang, cross_lang_routing } = req.body
    if (lang === undefined && cross_lang_routing === undefined) return res.json({ ok: true })

    if (lang !== undefined && !VALID_LANGS.has(lang))
      return res.status(400).json({ error: 'Invalid lang' })
    if (cross_lang_routing !== undefined && !VALID_ROUTING.has(cross_lang_routing))
      return res.status(400).json({ error: 'Invalid cross_lang_routing' })

    const userId = req.user.id
    const sets = []
    const vals = []
    if (lang !== undefined)              { sets.push(`lang = $${sets.length + 1}`);               vals.push(lang) }
    if (cross_lang_routing !== undefined){ sets.push(`cross_lang_routing = $${sets.length + 1}`); vals.push(cross_lang_routing) }
    vals.push(userId)
    await query(`UPDATE users SET ${sets.join(', ')} WHERE id = $${vals.length}`, vals)

    const { rows: [u] } = await query(
      'SELECT id, email, name, picture_url, lang, role, cross_lang_routing FROM users WHERE id = $1',
      [userId]
    )

    const sessionToken = signSessionToken({
      sub: u.id, email: u.email, name: u.name,
      picture: u.picture_url, lang: u.lang, role: u.role,
      cross_lang_routing: u.cross_lang_routing || 'ask',
    })

    res.cookie('pb_session', sessionToken, SESSION_COOKIE_OPTS)
    if (u.lang) res.cookie('pb_lang', u.lang, LANG_COOKIE_OPTS)

    res.json({ ok: true, lang: u.lang, cross_lang_routing: u.cross_lang_routing })
  } catch (err) {
    next(err)
  }
})

// ── DELETE /me — DPDP account + data erasure ─────────────────────────────────
// Hard-deletes the user row; oauth_identities and sessions cascade via FK
// (ON DELETE CASCADE). Clears all auth cookies so the device is logged out.
// This is the user's right to erasure under India's DPDP Act 2023.

router.delete('/', requireAuth, async (req, res, next) => {
  try {
    const userId = req.user.id

    // Confirmation guard: require explicit body { confirm: "DELETE" } so a
    // stray or forged DELETE can't erase an account.
    if (req.body?.confirm !== 'DELETE') {
      return res.status(400).json({ error: 'Send {"confirm":"DELETE"} to erase the account' })
    }

    const { rowCount } = await query('DELETE FROM users WHERE id = $1', [userId])

    for (const name of ['pb_session', 'pb_refresh', 'pb_lang']) {
      res.clearCookie(name, { domain: config.cookie.domain, path: '/' })
    }

    if (!rowCount) return res.status(404).json({ error: 'Account not found' })
    res.json({ ok: true, deleted: true })
  } catch (err) {
    next(err)
  }
})

// ── GET /me/check — fast unauthenticated cookie check (no DB hit) ─────────────

router.get('/check', (req, res) => {
  const token = req.cookies?.pb_session
  if (!token) return res.json({ authenticated: false })
  const payload = verifySessionToken(token)
  if (!payload) return res.json({ authenticated: false })
  res.json({ authenticated: true, sub: payload.sub, role: payload.role, lang: payload.lang })
})

export default router
