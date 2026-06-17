import { Router }     from 'express'
import { randomBytes } from 'crypto'
import config, { isSafeReturn, langToOrigin } from '../config.js'
import { generatePkce, getAuthUrl, exchangeCode, getUserInfo } from '../lib/google.js'
import { signSessionToken, hashToken } from '../lib/jwt.js'
import { query } from '../lib/db.js'
import { checkRateLimit } from '../lib/redis.js'
import { sendAlert } from '../lib/alerts.js'

const router = Router()

// In-memory state store: state → { return, verifier, expires }
// Short TTL (10 min) so it never grows large even under load.
const stateStore = new Map()
setInterval(() => {
  const now = Date.now()
  for (const [k, v] of stateStore) {
    if (v.expires < now) stateStore.delete(k)
  }
}, 60_000)

const SESSION_COOKIE_OPTS = {
  httpOnly: true,
  secure:   config.cookie.secure,
  sameSite: 'lax',
  domain:   config.cookie.domain,
  path:     '/',
}

const LANG_COOKIE_OPTS = {
  // NOT httpOnly — PHP + JS need to read this
  secure:   config.cookie.secure,
  sameSite: 'lax',
  domain:   config.cookie.domain,
  path:     '/',
}

function setSessionCookies(res, sessionToken, refreshToken, lang) {
  res.cookie('pb_session', sessionToken, {
    ...SESSION_COOKIE_OPTS,
    maxAge: config.jwt.sessionTtlSeconds * 1000,
  })
  if (refreshToken) {
    res.cookie('pb_refresh', refreshToken, {
      ...SESSION_COOKIE_OPTS,
      maxAge: config.jwt.refreshTtlDays * 24 * 60 * 60 * 1000,
    })
  }
  if (lang) {
    res.cookie('pb_lang', lang, {
      ...LANG_COOKIE_OPTS,
      maxAge: config.jwt.refreshTtlDays * 24 * 60 * 60 * 1000,
    })
  }
}

function clearAllCookies(res) {
  for (const name of ['pb_session', 'pb_refresh', 'pb_lang']) {
    res.clearCookie(name, { domain: config.cookie.domain, path: '/' })
  }
}

async function createSession(userId, ua, ip, ttlDays) {
  const raw   = randomBytes(48).toString('base64url')
  const hash  = hashToken(raw)
  const expires = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000)
  await query(
    `INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, hash, ua?.slice(0, 255), ip, expires]
  )
  return raw
}

function buildSessionToken(user) {
  return signSessionToken({
    sub:                user.id,
    email:              user.email,
    name:               user.name,
    picture:            user.picture_url,
    lang:               user.lang,
    role:               user.role,
    cross_lang_routing: user.cross_lang_routing || 'ask',
  })
}

// ── GET /login ────────────────────────────────────────────────────────────────

router.get('/login', async (req, res) => {
  const ip = req.ip
  const ok = await checkRateLimit(`rl:login:${ip}`, 20, 300)
  if (!ok) return res.status(429).json({ error: 'Too many requests' })

  const returnUrl = isSafeReturn(req.query.return) ? req.query.return : config.defaultRedirect
  const { verifier, challenge } = generatePkce()
  const state = randomBytes(16).toString('hex')
  stateStore.set(state, { return: returnUrl, verifier, expires: Date.now() + 10 * 60 * 1000 })

  res.redirect(getAuthUrl(state, challenge))
})

// ── GET /callback/google ──────────────────────────────────────────────────────

router.get('/callback/google', async (req, res, next) => {
  try {
    const { code, state, error } = req.query
    const ip = req.ip
    const ua = req.headers['user-agent']

    const ok = await checkRateLimit(`rl:callback:${ip}`, 20, 300)
    if (!ok) return res.status(429).json({ error: 'Too many requests' })

    if (error) return res.redirect(`${config.defaultRedirect}?auth_error=${encodeURIComponent(error)}`)
    if (!code || !state) return res.status(400).json({ error: 'Missing code or state' })

    const stateData = stateStore.get(state)
    if (!stateData) return res.redirect(`${config.defaultRedirect}?auth_error=invalid_state`)
    stateStore.delete(state)

    const returnUrl = isSafeReturn(stateData.return) ? stateData.return : config.defaultRedirect

    const tokens  = await exchangeCode(code, stateData.verifier)
    const profile = await getUserInfo(tokens.access_token)
    if (!profile.email) return res.redirect(`${config.defaultRedirect}?auth_error=no_email`)

    // Upsert user: find by Google sub (most common path) then by email, else create.
    let userId
    const { rows: byIdentity } = await query(
      `SELECT user_id FROM oauth_identities WHERE provider = 'google' AND provider_sub = $1`,
      [profile.sub]
    )
    if (byIdentity.length) {
      userId = byIdentity[0].user_id
      await query(
        `UPDATE users SET name = $1, picture_url = $2, last_login_at = NOW() WHERE id = $3`,
        [profile.name, profile.picture, userId]
      )
    } else {
      // New Google login — upsert user row by email (Google accounts with same email)
      const { rows: [u] } = await query(
        `INSERT INTO users (email, name, picture_url, last_login_at)
           VALUES ($1, $2, $3, NOW())
         ON CONFLICT (email) DO UPDATE
           SET name = EXCLUDED.name, picture_url = EXCLUDED.picture_url,
               last_login_at = NOW()
         RETURNING id`,
        [profile.email, profile.name, profile.picture]
      )
      userId = u.id
      await query(
        `INSERT INTO oauth_identities (user_id, provider, provider_sub) VALUES ($1, 'google', $2)
         ON CONFLICT DO NOTHING`,
        [userId, profile.sub]
      )
    }

    const { rows: [fullUser] } = await query(
      'SELECT id, email, name, picture_url, lang, role, cross_lang_routing FROM users WHERE id = $1',
      [userId]
    )

    const refreshToken = await createSession(userId, ua, ip, config.jwt.refreshTtlDays)
    const sessionToken = buildSessionToken(fullUser)

    setSessionCookies(res, sessionToken, refreshToken, fullUser.lang)

    // If lang not set → language onboarding first
    if (!fullUser.lang) {
      return res.redirect(`/language?return=${encodeURIComponent(returnUrl)}`)
    }
    res.redirect(returnUrl)
  } catch (err) {
    next(err)
  }
})

// ── POST /refresh ─────────────────────────────────────────────────────────────
// Silent re-auth for known devices (called by the WP gate JS on page load).

router.post('/refresh', async (req, res, next) => {
  try {
    const raw = req.cookies?.pb_refresh
    if (!raw) return res.status(401).json({ error: 'No refresh token' })

    const ip = req.ip
    const ok = await checkRateLimit(`rl:refresh:${ip}`, 30, 300)
    if (!ok) return res.status(429).json({ error: 'Too many requests' })

    const hash = hashToken(raw)

    const { rows } = await query(
      `SELECT s.id, s.user_id, s.rotated_from, s.revoked_at, s.expires_at,
              u.email, u.name, u.picture_url, u.lang, u.role, u.cross_lang_routing
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.refresh_token_hash = $1`,
      [hash]
    )

    if (!rows.length) {
      clearAllCookies(res)
      return res.status(401).json({ error: 'Unknown session' })
    }

    const session = rows[0]

    // Reuse detection: token already used (rotated_from chain leads here but
    // the token itself should no longer exist). If the session is revoked OR
    // its chain was compromised, revoke the whole user's sessions.
    if (session.revoked_at) {
      const { rowCount } = await query(
        'UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL',
        [session.user_id]
      )
      console.warn(`[auth] refresh token reuse detected for user ${session.user_id} from ${ip}`)
      // Whole chain revoked → alert ops. Dedupe per user so one stolen token
      // replayed repeatedly produces a single alert per 10 min.
      sendAlert(
        `⚠️ *Refresh token reuse detected*\n` +
        `User: \`${session.user_id}\`\n` +
        `IP: \`${ip}\`\n` +
        `Email: ${session.email || 'guest'}\n` +
        `Revoked ${rowCount} active session(s) for this user.`,
        { dedupeKey: `reuse:${session.user_id}`, dedupeTtl: 600 }
      )
      clearAllCookies(res)
      return res.status(401).json({ error: 'Session revoked' })
    }

    if (new Date(session.expires_at) < new Date()) {
      clearAllCookies(res)
      return res.status(401).json({ error: 'Session expired' })
    }

    // Rotate: revoke old token, issue new one
    const newRaw  = randomBytes(48).toString('base64url')
    const newHash = hashToken(newRaw)
    const expires = new Date(Date.now() + config.jwt.refreshTtlDays * 24 * 60 * 60 * 1000)
    const ua = req.headers['user-agent']

    await query(
      `UPDATE sessions SET revoked_at = NOW() WHERE id = $1`,
      [session.id]
    )
    await query(
      `INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip, expires_at, rotated_from)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [session.user_id, newHash, ua?.slice(0, 255), ip, expires, session.id]
    )

    const fullUser = {
      id: session.user_id, email: session.email, name: session.name,
      picture_url: session.picture_url, lang: session.lang, role: session.role,
    }
    const sessionToken = buildSessionToken(fullUser)
    setSessionCookies(res, sessionToken, newRaw, fullUser.lang)
    res.json({ ok: true })
  } catch (err) {
    next(err)
  }
})

// ── GET/POST /guest ─────────────────────────────────────────────────────────
// Mints a guest pb_session (full read access, no durable identity).
// Guest users get a short refresh token (7 days) so device recognition works.
// Bound to GET as well as POST because the gate's "Continue as guest" is a
// navigation link (like /login) — a GET that redirects through onboarding.

async function handleGuest(req, res, next) {
  try {
    const ip = req.ip
    const ok = await checkRateLimit(`rl:guest:${ip}`, 10, 300)
    if (!ok) return res.status(429).json({ error: 'Too many requests' })

    const returnUrl = isSafeReturn(req.query.return) ? req.query.return : config.defaultRedirect

    // Guests have no real identity. Give them a unique, non-routable synthetic
    // email so the NOT NULL + UNIQUE constraint on users.email is satisfied
    // without a schema change. The .invalid TLD is reserved (RFC 2606).
    const guestEmail = `guest-${randomBytes(16).toString('hex')}@guest.paisabot.invalid`
    const { rows: [user] } = await query(
      `INSERT INTO users (email, role) VALUES ($1, 'guest') RETURNING id, role, lang`,
      [guestEmail]
    )

    const ua = req.headers['user-agent']
    const refreshToken = await createSession(user.id, ua, ip, config.jwt.guestRefreshTtlDays)

    const sessionToken = signSessionToken({
      sub:  user.id,
      role: 'guest',
      lang: user.lang,
    })

    setSessionCookies(res, sessionToken, refreshToken, user.lang)

    // Guests also need language onboarding before getting routed
    if (!user.lang) {
      return res.redirect(`/language?return=${encodeURIComponent(returnUrl)}`)
    }
    res.redirect(returnUrl)
  } catch (err) {
    next(err)
  }
}

router.get('/guest', handleGuest)
router.post('/guest', handleGuest)

// ── GET/POST /logout ──────────────────────────────────────────────────────────

router.all('/logout', async (req, res, next) => {
  try {
    const raw = req.cookies?.pb_refresh
    if (raw) {
      const hash = hashToken(raw)
      await query(
        'UPDATE sessions SET revoked_at = NOW() WHERE refresh_token_hash = $1 AND revoked_at IS NULL',
        [hash]
      )
    }
    clearAllCookies(res)
    const returnUrl = isSafeReturn(req.query.return) ? req.query.return : config.defaultRedirect
    res.redirect(returnUrl)
  } catch (err) {
    next(err)
  }
})

export default router
