import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import config from '../config.js'

/**
 * Signs a short-lived access token (15 min).
 */
export function signAccessToken(payload) {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: '15m',
    issuer: 'auth.paisabot.com',
    audience: 'paisabot.com',
  })
}

/**
 * Verifies and decodes an access token.
 * Returns null if invalid or expired.
 */
export function verifyAccessToken(token) {
  try {
    return jwt.verify(token, config.jwt.secret, {
      issuer: 'auth.paisabot.com',
      audience: 'paisabot.com',
    })
  } catch {
    return null
  }
}

/**
 * Generates a secure opaque refresh token (64 hex chars).
 */
export function generateRefreshToken() {
  return crypto.randomBytes(32).toString('hex')
}
