export const securityConfig = () => ({
  security: {
    bcryptRounds: process.env.BCRYPT_ROUNDS ? Number(process.env.BCRYPT_ROUNDS) : 12,
    emailVerificationExpiry: process.env.EMAIL_VERIFICATION_EXPIRY ?? '24h',
    passwordResetExpiry: process.env.PASSWORD_RESET_EXPIRY ?? '1h',
    loginRateLimit: process.env.LOGIN_RATE_LIMIT ? Number(process.env.LOGIN_RATE_LIMIT) : 5,
    registrationRateLimit: process.env.REGISTRATION_RATE_LIMIT ? Number(process.env.REGISTRATION_RATE_LIMIT) : 3,
    emailRateLimit: process.env.EMAIL_RATE_LIMIT ? Number(process.env.EMAIL_RATE_LIMIT) : 3,
    lockDuration: process.env.ACCOUNT_LOCK_DURATION ?? '30m',
  },
});
