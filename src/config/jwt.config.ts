export const jwtConfig = () => ({
  jwt: {
    secret: process.env.JWT_SECRET ?? 'changeme',
    refreshSecret: process.env.JWT_REFRESH_SECRET ?? 'changeme-refresh',
    expiration: process.env.JWT_EXPIRATION ?? '15m',
    refreshExpiration: process.env.JWT_REFRESH_EXPIRATION ?? '7d',
  },
});
