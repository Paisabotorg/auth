import pg from 'pg'
import config from '../config.js'

const { Pool } = pg

export const pool = new Pool({
  connectionString: config.db.url,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
})

pool.on('error', (err) => {
  console.error('[db] unexpected pool error:', err.message)
})

export async function query(text, params) {
  const start = Date.now()
  const res = await pool.query(text, params)
  const duration = Date.now() - start
  if (duration > 500) console.warn(`[db] slow query (${duration}ms):`, text)
  return res
}
