/**
 * Variant API — cross-language story discovery for the interstitial.
 *
 * GET /api/v1/story/:cluster_id/variants
 *   Returns every published generated_post for this cluster_id.
 *   Response: { cluster_id, variants: [{lang, site, wp_post_id, wp_url}] }
 *   ETag + 1h Cache-Control so WP sites can cache aggressively.
 *
 * GET /api/v1/story/resolve?site=<host>&post=<wp_post_id>
 *   Reverse-lookup: given a WP site + post ID, return the cluster_id
 *   and all variants. Used by the mu-plugin to bootstrap the interstitial.
 */

import { Router }  from 'express'
import { createHash } from 'crypto'
import pg from 'pg'
import config from '../config.js'

const router = Router()
// variants reads generated_posts from the CMS DB, not the auth DB
const pool   = new pg.Pool({ connectionString: process.env.CMS_DATABASE_URL || config.db.url })

const CACHE_SECONDS = 3600
const VARIANT_FIELDS = `lang, site, wp_post_id, wp_url`

// lang → canonical subdomain (mirrors config.js)
const LANG_SUBDOMAIN = {
  en: 'www', hi: 'hi', bn: 'bn', mr: 'mr', te: 'tel',
  ta: 'ta', gu: 'gu', kn: 'kn', ml: 'ml', or: 'or',
}

function etag(data) {
  return '"' + createHash('sha1').update(JSON.stringify(data)).digest('hex').slice(0, 16) + '"'
}

function cacheHeaders(res) {
  res.set('Cache-Control', `public, max-age=${CACHE_SECONDS}`)
}

/**
 * Normalize a ?site= value to a lang code by reversing the subdomain map.
 * Accepts both hostname strings ("hi.paisabot.com") and full origin URLs.
 */
function siteToLang(site) {
  try {
    const host = new URL(site.startsWith('http') ? site : `https://${site}`).hostname
    const sub = host.split('.')[0]
    // reverse lookup
    for (const [lang, s] of Object.entries(LANG_SUBDOMAIN)) {
      if (s === sub || (sub === 'www' && lang === 'en') || (sub === 'paisabot' && lang === 'en')) {
        return lang
      }
    }
  } catch { /* fall through */ }
  return null
}

// GET /api/v1/story/:cluster_id/variants
router.get('/:cluster_id/variants', async (req, res) => {
  const { cluster_id } = req.params
  if (!/^[0-9a-f-]{36}$/i.test(cluster_id)) {
    return res.status(400).json({ error: 'invalid cluster_id' })
  }

  const { rows } = await pool.query(
    `SELECT ${VARIANT_FIELDS}
     FROM public.generated_posts
     WHERE cluster_id = $1
       AND status = 'published'
       AND wp_post_id IS NOT NULL
     ORDER BY lang`,
    [cluster_id],
  )

  const body = { cluster_id, variants: rows }
  const tag  = etag(body)
  if (req.headers['if-none-match'] === tag) {
    return res.status(304).end()
  }

  cacheHeaders(res)
  res.set('ETag', tag)
  res.json(body)
})

// GET /api/v1/story/resolve?site=<host>&post=<wp_post_id>
router.get('/resolve', async (req, res) => {
  const { site, post } = req.query
  const lang = siteToLang(site || '')
  const wp_post_id = parseInt(post, 10)

  if (!lang || !Number.isFinite(wp_post_id)) {
    return res.status(400).json({ error: 'site and post are required' })
  }

  // Find the cluster_id from the given site + post id
  const lookup = await pool.query(
    `SELECT cluster_id FROM public.generated_posts
     WHERE lang = $1 AND wp_post_id = $2 AND status = 'published'
     LIMIT 1`,
    [lang, wp_post_id],
  )

  if (lookup.rows.length === 0) {
    return res.status(404).json({ error: 'not found' })
  }

  const cluster_id = lookup.rows[0].cluster_id

  const { rows } = await pool.query(
    `SELECT ${VARIANT_FIELDS}
     FROM public.generated_posts
     WHERE cluster_id = $1
       AND status = 'published'
       AND wp_post_id IS NOT NULL
     ORDER BY lang`,
    [cluster_id],
  )

  const body = { cluster_id, variants: rows }
  const tag  = etag(body)
  if (req.headers['if-none-match'] === tag) {
    return res.status(304).end()
  }

  cacheHeaders(res)
  res.set('ETag', tag)
  res.json(body)
})

export default router
