import { Router } from 'express'
import config from '../config.js'
import { createRequestClient } from '../lib/supabase.js'

const router = Router()

/**
 * Validates that a redirect URL is safe (must be in allowedOrigins).
 */
function isSafeRedirect(url) {
  if (!url) return false
  try {
    const parsed = new URL(url)
    return config.allowedOrigins.some((origin) => {
      const o = new URL(origin)
      return parsed.origin === o.origin
    })
  } catch {
    return false
  }
}

/**
 * GET /auth/google
 * Initiates Google OAuth via Supabase.
 * Optional query param: ?next=https://analyse.paisabot.com/
 */
router.get('/google', async (req, res, next) => {
  try {
    const supabase = createRequestClient(req, res)
    const next_ = isSafeRedirect(req.query.next) ? req.query.next : config.defaultRedirect

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: `${config.baseUrl}/auth/callback?next=${encodeURIComponent(next_)}`,
        scopes: 'email profile',
        queryParams: { access_type: 'offline', prompt: 'consent' },
      },
    })

    if (error) return next(error)
    res.redirect(data.url)
  } catch (err) {
    next(err)
  }
})

/**
 * GET /auth/facebook
 * Initiates Facebook OAuth via Supabase.
 */
router.get('/facebook', async (req, res, next) => {
  try {
    const supabase = createRequestClient(req, res)
    const next_ = isSafeRedirect(req.query.next) ? req.query.next : config.defaultRedirect

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'facebook',
      options: {
        redirectTo: `${config.baseUrl}/auth/callback?next=${encodeURIComponent(next_)}`,
        scopes: 'email,public_profile',
      },
    })

    if (error) return next(error)
    res.redirect(data.url)
  } catch (err) {
    next(err)
  }
})

/**
 * GET /auth/instagram
 * Instagram login is handled through the Meta/Facebook OAuth provider.
 * Supabase maps 'instagram' to Meta's identity platform.
 */
router.get('/instagram', async (req, res, next) => {
  try {
    const supabase = createRequestClient(req, res)
    const next_ = isSafeRedirect(req.query.next) ? req.query.next : config.defaultRedirect

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'instagram',
      options: {
        redirectTo: `${config.baseUrl}/auth/callback?next=${encodeURIComponent(next_)}`,
      },
    })

    if (error) return next(error)
    res.redirect(data.url)
  } catch (err) {
    next(err)
  }
})

/**
 * GET /auth/callback
 * Supabase redirects here after OAuth with a PKCE code.
 * Exchanges code → session, sets HttpOnly cookies, redirects user.
 */
router.get('/callback', async (req, res, next) => {
  try {
    const supabase = createRequestClient(req, res)
    const code = req.query.code
    const next_ = isSafeRedirect(req.query.next) ? req.query.next : config.defaultRedirect

    if (!code) {
      return res.status(400).json({ error: 'Missing auth code' })
    }

    const { error } = await supabase.auth.exchangeCodeForSession(code)

    if (error) {
      console.error('[auth/callback] exchange error:', error.message)
      return res.redirect(`${config.defaultRedirect}?auth_error=1`)
    }

    // Cookies are set automatically by the SSR client via setAll()
    res.redirect(next_)
  } catch (err) {
    next(err)
  }
})

/**
 * POST /auth/logout
 * Signs the user out and clears session cookies.
 */
router.post('/logout', async (req, res, next) => {
  try {
    const supabase = createRequestClient(req, res)
    await supabase.auth.signOut()

    // Belt-and-suspenders: clear known cookie names
    const cookieOpts = {
      domain: config.cookie.domain,
      path: '/',
      secure: config.cookie.secure,
      httpOnly: true,
      sameSite: 'lax',
    }
    res.clearCookie('sb-access-token', cookieOpts)
    res.clearCookie('sb-refresh-token', cookieOpts)
    res.clearCookie(`sb-${process.env.SUPABASE_PROJECT_REF}-auth-token`, cookieOpts)

    const redirectTo = isSafeRedirect(req.query.next) ? req.query.next : config.defaultRedirect
    res.redirect(redirectTo)
  } catch (err) {
    next(err)
  }
})

export default router
