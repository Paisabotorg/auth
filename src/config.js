import 'dotenv/config'

const required = (key) => {
  if (!process.env[key]) throw new Error(`Missing required env var: ${key}`)
  return process.env[key]
}

export default {
  port: parseInt(process.env.PORT || '3100', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  db: {
    url: required('DATABASE_URL'),
  },

  jwt: {
    secret: required('JWT_SECRET'),
  },

  google: {
    clientId: required('GOOGLE_CLIENT_ID'),
    clientSecret: required('GOOGLE_CLIENT_SECRET'),
    redirectUri: process.env.GOOGLE_REDIRECT_URI || 'https://auth.paisabot.com/auth/callback',
  },

  baseUrl: process.env.BASE_URL || 'https://auth.paisabot.com',
  defaultRedirect: process.env.DEFAULT_REDIRECT || 'https://paisabot.com',

  cookie: {
    domain: process.env.COOKIE_DOMAIN || '.paisabot.com',
    secure: process.env.NODE_ENV === 'production',
  },

  allowedOrigins: [
    'https://paisabot.com',
    'https://www.paisabot.com',
    'https://qa.paisabot.com',
    'https://hi.paisabot.com',
    'https://ml.paisabot.com',
    'https://tel.paisabot.com',
    'https://analyse.paisabot.com',
    'https://markets.paisabot.com',
    'https://api.paisabot.com',
    'http://localhost:3000',
    'http://localhost:8080',
  ],

  allowedRedirects: [
    'https://paisabot.com',
    'https://www.paisabot.com',
    'https://qa.paisabot.com',
    'https://hi.paisabot.com',
    'https://ml.paisabot.com',
    'https://tel.paisabot.com',
    'https://analyse.paisabot.com',
    'https://markets.paisabot.com',
  ],
}
