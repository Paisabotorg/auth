#!/usr/bin/env node
// Generates an RSA-2048 keypair for RS256 JWT signing.
// Run once: node scripts/generate-keys.js
// Writes private.pem and public.pem to the keys/ directory.

import { generateKeyPairSync } from 'crypto'
import { writeFileSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'keys')
mkdirSync(dir, { recursive: true })

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
})

writeFileSync(join(dir, 'private.pem'), privateKey, { mode: 0o600 })
writeFileSync(join(dir, 'public.pem'),  publicKey,  { mode: 0o644 })

console.log('Keys written to keys/private.pem and keys/public.pem')
console.log('Set PB_AUTH_PRIVATE_KEY_PATH and PB_AUTH_PUBLIC_KEY_PATH in .env')
