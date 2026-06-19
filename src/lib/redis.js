import { createClient } from 'redis'
import config from '../config.js'

const client = createClient({
  url: config.redis.url,
  // Keep retrying instead of giving up, so a Redis blip self-heals.
  socket: { reconnectStrategy: (retries) => Math.min(retries * 200, 5000) },
})

client.on('error', (err) => console.error('[redis]', err.message))

// Connect in the BACKGROUND — never block module load on Redis. A previous
// top-level `await client.connect()` here meant a Redis outage rejected at
// import time and crashed the whole auth service (login down, 502). node-redis
// auto-reconnects per the strategy above, so this recovers on its own.
client.connect().catch((err) =>
  console.error('[redis] initial connect failed (will retry):', err.message))

export default client

/**
 * Increment a rate-limit counter keyed by `key`. Returns true if under limit.
 * Fails OPEN: if Redis is unavailable, allow the request rather than taking auth
 * down. The per-IP express-rate-limit in index.js remains as a backstop.
 * @param {string} key
 * @param {number} max   max hits allowed
 * @param {number} ttl   window in seconds
 */
export async function checkRateLimit(key, max, ttl) {
  if (!client.isReady) return true
  try {
    const count = await client.incr(key)
    if (count === 1) await client.expire(key, ttl)
    return count <= max
  } catch (err) {
    console.error('[redis] rate-limit check failed, failing open:', err.message)
    return true
  }
}
