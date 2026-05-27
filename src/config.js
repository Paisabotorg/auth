import 'dotenv/config'

const required = (key) => {
  if (!process.env[key]) throw new Error(`Missing required env var: ${key}`)
  return process.env[key]
}

export default {
  port: parseInt(process.env.PORT || '3100', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  supabase: {
    url: required('SUPABASE_URL'),
    anonKey: required('SUPABASE_ANON_KEY'),
    serviceRoleKey: required('SUPABASE_SERVICE_ROLE_KEY'),
  },

  // Base URL of this auth service
  baseUrl: process.env.BASE_URL || 'https://auth.paisabot.com',

  // Where to send users after successful login
  defaultRedirect: process.env.DEFAULT_REDIRECT || 'https://paisabot.com',

  // Cookie settings
  cookie: {
    domain: process.env.COOKIE_DOMAIN || '.paisabot.com',
    secure: process.env.NODE_ENV === 'production',
  },

  // Allowed redirect origins after login
  allowedOrigins: [
    'https://paisabot.com',
    'https://qa.paisabot.com',
    'https://analyse.paisabot.com',
    'https://markets.paisabot.com',
    'https://api.paisabot.com',
    'http://localhost:3000',
    'http://localhost:8080',
  ],
}
