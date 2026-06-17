import { createClient } from 'redis'
import config from '../config.js'

const client = createClient({ url: config.redis.url })

client.on('error', (err) => console.error('[redis]', err.message))

await client.connect()

export default client

/**
 * Increment a rate-limit counter keyed by `key`. Returns true if under limit.
 * @param {string} key
 * @param {number} max   max hits allowed
 * @param {number} ttl   window in seconds
 */
export async function checkRateLimit(key, max, ttl) {
  const count = await client.incr(key)
  if (count === 1) await client.expire(key, ttl)
  return count <= max
}
