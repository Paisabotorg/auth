import { Router } from 'express'
import { createRequestClient } from '../lib/supabase.js'
import { adminClient } from '../lib/supabase.js'

const router = Router()

/**
 * GET /me
 * Returns the authenticated user's profile + subscription tier.
 * Called by analyse.paisabot.com and other frontends with credentials: 'include'.
 */
router.get('/', async (req, res, next) => {
  try {
    const supabase = createRequestClient(req, res)
    const { data: { user }, error } = await supabase.auth.getUser()

    if (error || !user) {
      return res.status(401).json({ authenticated: false })
    }

    // Fetch subscription info from Supabase (if table exists)
    let subscription = null
    try {
      const { data } = await adminClient
        .from('subscriptions')
        .select('tier, status, expires_at')
        .eq('user_id', user.id)
        .single()
      subscription = data
    } catch {
      // Table may not exist yet — not fatal
    }

    res.json({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.user_metadata?.full_name || user.user_metadata?.name,
        avatar: user.user_metadata?.avatar_url || user.user_metadata?.picture,
        provider: user.app_metadata?.provider,
      },
      subscription: subscription
        ? {
            tier: subscription.tier || 'free',
            status: subscription.status || 'active',
            expiresAt: subscription.expires_at,
          }
        : { tier: 'free', status: 'active', expiresAt: null },
    })
  } catch (err) {
    next(err)
  }
})

/**
 * GET /me/session
 * Returns raw Supabase session tokens — used by server-side PHP to verify JWT.
 * Only returns access_token (not refresh_token).
 */
router.get('/session', async (req, res, next) => {
  try {
    const supabase = createRequestClient(req, res)
    const { data: { session }, error } = await supabase.auth.getSession()

    if (error || !session) {
      return res.status(401).json({ authenticated: false })
    }

    res.json({
      authenticated: true,
      accessToken: session.access_token,
      expiresAt: session.expires_at,
    })
  } catch (err) {
    next(err)
  }
})

export default router
