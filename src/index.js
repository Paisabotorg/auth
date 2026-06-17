import 'dotenv/config'
import express      from 'express'
import cookieParser from 'cookie-parser'
import helmet       from 'helmet'
import cors         from 'cors'
import rateLimit    from 'express-rate-limit'
import { randomBytes } from 'crypto'

import config       from './config.js'
import authRouter   from './routes/auth.js'
import meRouter     from './routes/me.js'
import sessionsRouter from './routes/sessions.js'
import jwksRouter   from './routes/jwks.js'
import languageRouter from './routes/language.js'
import variantsRouter from './routes/variants.js'

const app = express()

// Per-request CSP nonce — lets the language picker's first-party inline script
// run under a strict script-src without allowing 'unsafe-inline'.
app.use((req, res, next) => {
  res.locals.cspNonce = randomBytes(16).toString('base64')
  next()
})

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:', 'https://lh3.googleusercontent.com'],
      connectSrc: ["'self'"],
      // POST /language redirects to the chosen-lang site, so form-action must
      // allow the paisabot domains (Chrome enforces form-action on the redirect
      // target of a form submission, not just the initial action URL).
      formAction: ["'self'", 'https://accounts.google.com', 'https://paisabot.com', 'https://*.paisabot.com'],
      frameAncestors: ["'none'"],
      objectSrc:  ["'none'"],
      baseUri:    ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  // 2-year HSTS with preload — auth.paisabot.com is HTTPS-only behind nginx
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  frameguard: { action: 'deny' },
}))

// Strip the framework fingerprint
app.disable('x-powered-by')

app.set('trust proxy', 1)

app.use(cors({
  origin:      config.allowedOrigins,
  credentials: true,
  methods:     ['GET', 'POST', 'PATCH', 'OPTIONS'],
}))

// Global soft rate-limit (per-endpoint limits are applied in auth.js).
// JWKS + health are hit constantly by WP sites — exempt them so the gate
// never gets throttled on the hot path.
app.use(rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             300,
  standardHeaders: true,
  legacyHeaders:   false,
  skip:            (req) =>
    req.path === '/health' ||
    req.path === '/.well-known/jwks.json' ||
    req.path.startsWith('/api/v1/story'),
}))

// Tighter limiter for state-changing auth endpoints (login, callback, guest,
// refresh, logout, account deletion). Per-IP, in addition to the Redis limits
// inside auth.js. Protects against credential-stuffing / token brute force.
const authLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             60,
  standardHeaders: true,
  legacyHeaders:   false,
})

app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())

app.use('/login',         authLimiter)
app.use('/callback',      authLimiter)
app.use('/guest',         authLimiter)
app.use('/refresh',       authLimiter)
app.use('/',              authRouter)       // /login, /callback/google, /refresh, /guest, /logout
app.use('/me',            meRouter)
app.use('/sessions',      sessionsRouter)
app.use('/.well-known',   jwksRouter)
app.use('/language',      languageRouter)
app.use('/api/v1/story',  variantsRouter)

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'paisabot-auth', ts: new Date().toISOString() })
})

app.use((err, _req, res, _next) => {
  console.error('[error]', err.message)
  res.status(500).json({ error: 'Internal server error' })
})

app.listen(config.port, () => {
  console.log(`[paisabot-auth] running on port ${config.port} (${config.nodeEnv})`)
})

export default app
