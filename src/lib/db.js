import pg from 'pg'
import config from '../config.js'

const { Pool } = pg

export const pool = new Pool({
  connectionString: config.db.url,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  // Route all queries to the auth schema by default
  options: '--search_path=paisabot_auth,public',
})

pool.on('error', (err) => {
  console.error('[db] pool error:', err.message)
})

export async function query(text, params) {
  const start = Date.now()
  const res = await pool.query(text, params)
  const ms = Date.now() - start
  if (ms > 500) console.warn(`[db] slow query (${ms}ms):`, text.slice(0, 120))
  return res
}
