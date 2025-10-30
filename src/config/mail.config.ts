export const mailConfig = () => ({
  mail: {
    host: process.env.MAIL_HOST ?? 'smtp.gmail.com',
    port: process.env.MAIL_PORT ? Number(process.env.MAIL_PORT) : 587,
    user: process.env.MAIL_USER ?? '',
    pass: process.env.MAIL_PASS ?? '',
    from: process.env.MAIL_FROM ?? 'no-reply@example.com',
  },
});
