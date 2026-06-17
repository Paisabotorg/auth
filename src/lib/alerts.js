/**
 * alerts.js — security/ops alerts via Telegram.
 *
 * Configured by env (all optional — if unset, alerts silently no-op so the
 * auth service never fails because of alerting):
 *   PB_ALERT_TELEGRAM_TOKEN    bot token (falls back to TELEGRAM_BOT_TOKEN)
 *   PB_ALERT_TELEGRAM_CHAT_ID  destination chat id
 *
 * Alerts are fire-and-forget and rate-limited per key via Redis so a flood
 * of the same event (e.g. a token-reuse storm) can't spam the channel.
 */
import { checkRateLimit } from './redis.js'

const TOKEN   = process.env.PB_ALERT_TELEGRAM_TOKEN || process.env.TELEGRAM_BOT_TOKEN || ''
const CHAT_ID = process.env.PB_ALERT_TELEGRAM_CHAT_ID || ''
const ENABLED = Boolean(TOKEN && CHAT_ID)

if (!ENABLED) {
  console.warn('[alerts] Telegram alerts disabled (set PB_ALERT_TELEGRAM_TOKEN + PB_ALERT_TELEGRAM_CHAT_ID)')
}

/**
 * Send a Telegram alert. Never throws.
 * @param {string} text     message (Markdown)
 * @param {object} [opts]
 * @param {string} [opts.dedupeKey]   suppress identical alerts within dedupeTtl
 * @param {number} [opts.dedupeTtl=300] seconds to suppress duplicates
 */
export async function sendAlert(text, opts = {}) {
  if (!ENABLED) return
  try {
    if (opts.dedupeKey) {
      // checkRateLimit returns false once the count exceeds max; allow exactly 1
      const allowed = await checkRateLimit(`alert:${opts.dedupeKey}`, 1, opts.dedupeTtl ?? 300)
      if (!allowed) return
    }
    const body = {
      chat_id: CHAT_ID,
      text:    `🔐 *Paisabot Auth*\n${text}`,
      parse_mode: 'Markdown',
      disable_web_page_preview: true,
    }
    const r = await fetch(`https://api.telegram.org/bot${TOKEN}/sendMessage`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    })
    if (!r.ok) console.warn('[alerts] telegram send failed:', r.status)
  } catch (e) {
    console.warn('[alerts] telegram error:', e.message)
  }
}
