import { Router } from 'express'
import { JWKS } from '../lib/jwt.js'

const router = Router()

router.get('/jwks.json', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=86400')
  res.json(JWKS)
})

export default router
