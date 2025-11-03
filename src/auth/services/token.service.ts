import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes, createHash } from 'crypto';
import ms, { type StringValue } from 'ms';

interface TokenResult {
  token: string;
  hashedToken: string;
  expiresAt: Date;
}

@Injectable()
export class TokenService {
  constructor(private readonly configService: ConfigService) {}

  createEmailVerificationToken(): TokenResult {
    const expiry = this.configService.get<string>('security.emailVerificationExpiry');
    return this.createSecureToken(expiry, '24h' as StringValue);
  }

  createPasswordResetToken(): TokenResult {
    const expiry = this.configService.get<string>('security.passwordResetExpiry');
    return this.createSecureToken(expiry, '1h' as StringValue);
  }

  createRefreshToken(): TokenResult {
    const expiry = this.configService.get<string>('jwt.refreshExpiration');
    return this.createSecureToken(expiry, '7d' as StringValue);
  }

  private createSecureToken(expiryConfig: string | undefined, fallback: StringValue): TokenResult {
    const token = randomBytes(32).toString('hex');
    const hashedToken = createHash('sha256').update(token).digest('hex');
    const expiresInMs = this.resolveExpiry(expiryConfig, fallback);
    const expiresAt = new Date(Date.now() + expiresInMs);
    return { token, hashedToken, expiresAt };
  }

  private resolveExpiry(value: string | undefined, fallback: StringValue): number {
    const raw = (value ?? fallback) as StringValue;
    const parsed = ms(raw);
    if (typeof parsed !== 'number') {
      const fallbackParsed = ms(fallback);
      if (typeof fallbackParsed !== 'number') {
        throw new Error(`Invalid expiry configuration for value: ${raw}`);
      }
      return fallbackParsed;
    }
    return parsed;
  }
}
