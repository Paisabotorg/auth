module.exports = {
  apps: [
    {
      name: 'paisabot-auth',
      script: 'src/index.js',
      instances: 1,
      exec_mode: 'fork',
      node_args: '--experimental-vm-modules',
      env_production: {
        NODE_ENV: 'production',
        PORT: 3100,
      },
      watch: false,
      max_memory_restart: '256M',
      error_file: '/var/log/paisabot/auth-error.log',
      out_file: '/var/log/paisabot/auth-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      restart_delay: 5000,
      max_restarts: 10,
    },
  ],
}
