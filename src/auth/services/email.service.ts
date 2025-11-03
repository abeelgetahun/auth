import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);

  constructor(
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
  ) {}

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const baseUrl = this.configService.get<string>('betterAuth.url', 'http://localhost:3000');
    const verificationUrl = `${baseUrl}/auth/verify-email/${token}`;
    await this.dispatch(email, 'Verify your email address', 'verify-email', {
      verificationUrl,
    });
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const baseUrl = this.configService.get<string>('betterAuth.url', 'http://localhost:3000');
    const resetUrl = `${baseUrl}/auth/reset-password?token=${token}`;
    await this.dispatch(email, 'Reset your password', 'reset-password', {
      resetUrl,
    });
  }

  private async dispatch(to: string, subject: string, template: string, context: Record<string, unknown>): Promise<void> {
    try {
      await this.mailerService.sendMail({
        to,
        subject,
        template,
        context,
      });
    } catch (error) {
      this.logger.error(`Failed to send ${template} email`, error as Error);
      throw error;
    }
  }
}
