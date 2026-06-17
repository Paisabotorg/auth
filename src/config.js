import 'dotenv/config'
import { readFileSync } from 'fs'

const required = (key) => {
  if (!process.env[key]) throw new Error(`Missing required env var: ${key}`)
  return process.env[key]
}

const privateKeyPath = required('PB_AUTH_PRIVATE_KEY_PATH')
const publicKeyPath  = required('PB_AUTH_PUBLIC_KEY_PATH')

// lang code → canonical subdomain (te is the trap: lang=te, subdomain=tel)
export const LANG_SUBDOMAIN = {
  en: 'www',
  hi: 'hi',
  bn: 'bn',
  mr: 'mr',
  te: 'tel',
  ta: 'ta',
  gu: 'gu',
  kn: 'kn',
  ml: 'ml',
  or: 'or',
}

// Derive full origin from lang code
export function langToOrigin(lang) {
  const sub = LANG_SUBDOMAIN[lang]
  if (!sub) return null
  return sub === 'www'
    ? 'https://paisabot.com'
    : `https://${sub}.paisabot.com`
}

const ALLOWED_ORIGINS = [
  'https://paisabot.com',
  'https://www.paisabot.com',
  'https://qa.paisabot.com',
  'https://hi.paisabot.com',
  'https://bn.paisabot.com',
  'https://mr.paisabot.com',
  'https://tel.paisabot.com',
  'https://ta.paisabot.com',
  'https://gu.paisabot.com',
  'https://kn.paisabot.com',
  'https://ml.paisabot.com',
  'https://or.paisabot.com',
  'https://analyse.paisabot.com',
  'https://markets.paisabot.com',
  'https://api.paisabot.com',
  'https://auth.paisabot.com',
  'http://localhost:3000',
  'http://localhost:8080',
]

// Allowlist for ?return= redirects after login
const RETURN_ALLOWLIST_RE = /^https:\/\/([a-z]+\.)?paisabot\.com\//

export function isSafeReturn(url) {
  if (!url) return false
  try {
    const parsed = new URL(url)
    return RETURN_ALLOWLIST_RE.test(parsed.href) && parsed.protocol === 'https:'
  } catch {
    return false
  }
}

export default {
  port: parseInt(process.env.PORT || '3100', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  db: {
    url: required('DATABASE_URL'),
  },

  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },

  jwt: {
    privateKey: readFileSync(privateKeyPath, 'utf8'),
    publicKey:  readFileSync(publicKeyPath, 'utf8'),
    kid: process.env.PB_AUTH_KID || 'pb-auth-v1',
    issuer: 'https://auth.paisabot.com',
    sessionTtlSeconds: 60 * 60,           // 1 hour
    refreshTtlDays:    60,
    guestRefreshTtlDays: 7,
  },

  google: {
    clientId:     required('GOOGLE_CLIENT_ID'),
    clientSecret: required('GOOGLE_CLIENT_SECRET'),
    redirectUri:  process.env.GOOGLE_REDIRECT_URI || 'https://auth.paisabot.com/callback/google',
  },

  cookie: {
    domain: process.env.COOKIE_DOMAIN || '.paisabot.com',
    secure: process.env.NODE_ENV === 'production',
  },

  defaultRedirect: process.env.DEFAULT_REDIRECT || 'https://paisabot.com',
  allowedOrigins: ALLOWED_ORIGINS,
}
