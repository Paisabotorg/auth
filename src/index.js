import 'dotenv/config'
import express from 'express'
import cookieParser from 'cookie-parser'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'

import config from './config.js'
import authRouter from './routes/auth.js'
import meRouter from './routes/me.js'

const app = express()

// ── Security ──────────────────────────────────────────────
app.use(helmet())
app.set('trust proxy', 1) // Behind nginx

app.use(cors({
  origin: config.allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
}))

// ── Rate limiting ─────────────────────────────────────────
app.use('/auth', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
}))

app.use('/me', rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
}))

// ── Body / cookies ────────────────────────────────────────
app.use(express.json())
app.use(cookieParser())

// ── Routes ────────────────────────────────────────────────
app.use('/auth', authRouter)
app.use('/me', meRouter)

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'paisabot-auth', ts: new Date().toISOString() })
})

// ── Error handler ─────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[error]', err.message)
  res.status(500).json({ error: 'Internal server error' })
})

app.listen(config.port, () => {
  console.log(`[paisabot-auth] running on port ${config.port} (${config.nodeEnv})`)
})

export default app
