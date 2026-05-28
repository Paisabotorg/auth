import { Router } from 'express'
import crypto from 'crypto'
import config from '../config.js'
import { getAuthUrl, exchangeCode, getUserInfo } from '../lib/google.js'
import { signAccessToken, generateRefreshToken } from '../lib/jwt.js'
import { query } from '../lib/db.js'

const router = Router()

// In-memory state store (OAuth CSRF protection) — keyed by state param, TTL 10min
const stateStore = new Map()
setInterval(() => {
  const now = Date.now()
  for (const [k, v] of stateStore) {
    if (v.expires < now) stateStore.delete(k)
  }
}, 60_000)

const COOKIE_OPTS = {
  httpOnly: true,
  secure: config.cookie.secure,
  sameSite: 'lax',
  domain: config.cookie.domain,
  path: '/',
}

function isSafeRedirect(url) {
  if (!url) return false
  try {
    const parsed = new URL(url)
    return config.allowedRedirects.some((o) => new URL(o).origin === parsed.origin)
  } catch {
    return false
  }
}

function setTokenCookies(res, accessToken, refreshToken) {
  res.cookie('pb_token', accessToken, {
    ...COOKIE_OPTS,
    maxAge: 15 * 60 * 1000, // 15 min
  })
  res.cookie('pb_refresh', refreshToken, {
    ...COOKIE_OPTS,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  })
}

function clearTokenCookies(res) {
  res.clearCookie('pb_token', COOKIE_OPTS)
  res.clearCookie('pb_refresh', COOKIE_OPTS)
}

/**
 * GET /auth/google
 * Initiates Google OAuth. Optional ?next= for post-login redirect.
 */
router.get('/google', (req, res) => {
  const next = isSafeRedirect(req.query.next) ? req.query.next : config.defaultRedirect
  const state = crypto.randomBytes(16).toString('hex')
  stateStore.set(state, { next, expires: Date.now() + 10 * 60 * 1000 })
  res.redirect(getAuthUrl(state))
})

/**
 * GET /auth/callback
 * Google redirects here with ?code and ?state.
 */
router.get('/callback', async (req, res, next) => {
  try {
    const { code, state, error } = req.query

    if (error) return res.redirect(`${config.defaultRedirect}?auth_error=${error}`)
    if (!code || !state) return res.status(400).json({ error: 'Missing code or state' })

    const stateData = stateStore.get(state)
    if (!stateData) return res.redirect(`${config.defaultRedirect}?auth_error=invalid_state`)
    stateStore.delete(state)

    const redirectTo = isSafeRedirect(stateData.next) ? stateData.next : config.defaultRedirect

    // Exchange code for Google tokens
    const tokens = await exchangeCode(code)
    const profile = await getUserInfo(tokens.access_token)

    if (!profile.email) return res.redirect(`${config.defaultRedirect}?auth_error=no_email`)

    // Upsert user
    const { rows: [user] } = await query(
      `INSERT INTO users (email, name, avatar, google_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (google_id) DO UPDATE
         SET email = EXCLUDED.email,
             name = EXCLUDED.name,
             avatar = EXCLUDED.avatar,
             updated_at = NOW()
       RETURNING id, email, name, avatar`,
      [profile.email, profile.name, profile.picture, profile.sub]
    )

    // Ensure user_prefs row exists
    await query(
      `INSERT INTO user_prefs (user_id) VALUES ($1) ON CONFLICT DO NOTHING`,
      [user.id]
    )

    // Ensure subscriptions row exists
    await query(
      `INSERT INTO subscriptions (user_id) VALUES ($1) ON CONFLICT DO NOTHING`,
      [user.id]
    )

    // Create session
    const refreshToken = generateRefreshToken()
    await query(
      `INSERT INTO sessions (user_id, refresh_token, expires_at, ip, user_agent)
       VALUES ($1, $2, NOW() + INTERVAL '30 days', $3, $4)`,
      [user.id, refreshToken, req.ip, req.headers['user-agent']?.slice(0, 255)]
    )

    // Sign access token
    const accessToken = signAccessToken({
      sub: user.id,
      email: user.email,
      name: user.name,
    })

    setTokenCookies(res, accessToken, refreshToken)
    res.redirect(redirectTo)
  } catch (err) {
    next(err)
  }
})

/**
 * POST /auth/refresh
 * Silently refreshes the access token using the refresh token cookie.
 */
router.post('/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.pb_refresh
    if (!refreshToken) return res.status(401).json({ error: 'No refresh token' })

    const { rows } = await query(
      `SELECT s.id, s.user_id, u.email, u.name, u.avatar
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.refresh_token = $1 AND s.expires_at > NOW()`,
      [refreshToken]
    )

    if (!rows.length) {
      clearTokenCookies(res)
      return res.status(401).json({ error: 'Session expired' })
    }

    const { user_id, email, name } = rows[0]
    const newAccessToken = signAccessToken({ sub: user_id, email, name })

    res.cookie('pb_token', newAccessToken, {
      ...COOKIE_OPTS,
      maxAge: 15 * 60 * 1000,
    })

    res.json({ ok: true })
  } catch (err) {
    next(err)
  }
})

/**
 * POST /auth/logout
 */
router.post('/logout', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.pb_refresh
    if (refreshToken) {
      await query('DELETE FROM sessions WHERE refresh_token = $1', [refreshToken])
    }
    clearTokenCookies(res)
    const redirectTo = isSafeRedirect(req.query.next) ? req.query.next : config.defaultRedirect
    res.redirect(redirectTo)
  } catch (err) {
    next(err)
  }
})

export default router
