import jwt from 'jsonwebtoken'
import { createHash, createPublicKey } from 'crypto'
import config from '../config.js'

// Build the JWKS representation of the public key once at startup.
// Node's crypto can export a key object as JWK directly.
const _pubKeyObj = createPublicKey(config.jwt.publicKey)
const _jwk = _pubKeyObj.export({ format: 'jwk' })

export const JWKS = {
  keys: [{
    ..._jwk,
    use: 'sig',
    alg: 'RS256',
    kid: config.jwt.kid,
  }],
}

export function signSessionToken(payload) {
  return jwt.sign(payload, config.jwt.privateKey, {
    algorithm:  'RS256',
    expiresIn:  config.jwt.sessionTtlSeconds,
    issuer:     config.jwt.issuer,
    keyid:      config.jwt.kid,
  })
}

export function verifySessionToken(token) {
  try {
    return jwt.verify(token, config.jwt.publicKey, {
      algorithms: ['RS256'],
      issuer:     config.jwt.issuer,
    })
  } catch {
    return null
  }
}

// Refresh tokens are opaque random hex; we store only their SHA-256 hash.
export function hashToken(raw) {
  return createHash('sha256').update(raw).digest('hex')
}
