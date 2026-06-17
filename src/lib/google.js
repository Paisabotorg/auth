import { randomBytes, createHash } from 'crypto'
import config from '../config.js'

const GOOGLE_AUTH_URL  = 'https://accounts.google.com/o/oauth2/v2/auth'
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'

export function generatePkce() {
  const verifier  = randomBytes(40).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge }
}

export function getAuthUrl(state, challenge) {
  const params = new URLSearchParams({
    client_id:             config.google.clientId,
    redirect_uri:          config.google.redirectUri,
    response_type:         'code',
    scope:                 'openid email profile',
    access_type:           'offline',
    prompt:                'select_account',
    state,
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  })
  return `${GOOGLE_AUTH_URL}?${params}`
}

export async function exchangeCode(code, verifier) {
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     config.google.clientId,
      client_secret: config.google.clientSecret,
      redirect_uri:  config.google.redirectUri,
      grant_type:    'authorization_code',
      code_verifier: verifier,
    }),
  })
  if (!res.ok) throw new Error(`Google token exchange failed: ${await res.text()}`)
  return res.json()
}

export async function getUserInfo(accessToken) {
  const res = await fetch(GOOGLE_USERINFO_URL, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  if (!res.ok) throw new Error('Failed to fetch Google user info')
  return res.json()
}
