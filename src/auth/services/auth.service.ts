import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma, User } from '@prisma/client';
import { compare, hash } from 'bcrypt';
import { randomUUID, createHash } from 'crypto';
import ms, { type StringValue } from 'ms';

import { PrismaService } from '../../prisma/prisma.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyEmailDto } from '../dto/verify-email.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { TokenService } from './token.service';
import { EmailService } from './email.service';
import { AuthResult, AuthTokens } from '../interfaces/auth-result.interface';
import { SafeUser } from '../interfaces/user.interface';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly passwordHistoryLimit = 5;

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly emailService: EmailService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(dto: RegisterDto): Promise<SafeUser> {
    await this.ensureUserIsOfAge(dto.dateOfBirth);

    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) {
      throw new ConflictException('An account already exists for this email');
    }

    const saltRounds = this.configService.get<number>('security.bcryptRounds', 12);
    const passwordHash = await hash(dto.password, saltRounds);
    const emailToken = this.tokenService.createEmailVerificationToken();

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: passwordHash,
        name: dto.name,
        dateOfBirth: new Date(dto.dateOfBirth),
        address: dto.address,
        emailVerificationToken: emailToken.hashedToken,
        emailVerificationExpires: emailToken.expiresAt,
        passwordHistories: {
          create: {
            password: passwordHash,
          },
        },
      },
    });

    await this.emailService.sendVerificationEmail(user.email, emailToken.token);

    return this.sanitizeUser(user);
  }

  async login(dto: LoginDto, context: { ipAddress?: string; userAgent?: string }): Promise<AuthResult> {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (!user || !user.password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    this.ensureAccountIsActive(user);
    await this.ensureAccountIsNotLocked(user);

    const validPassword = await compare(dto.password, user.password);
    if (!validPassword) {
      await this.recordFailedAttempt(user);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.emailVerified) {
      throw new ForbiddenException('Email verification required');
    }

    await this.resetFailedAttempts(user.id);

    const tokens = await this.createSession(user, context);

    return {
      user: this.sanitizeUser(user),
      tokens,
    };
  }

  async verifyEmail(dto: VerifyEmailDto): Promise<void> {
    const hashed = createHash('sha256').update(dto.token).digest('hex');
    const user = await this.prisma.user.findFirst({
      where: {
        emailVerificationToken: hashed,
        emailVerificationExpires: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      throw new BadRequestException('Verification token is invalid or expired');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationToken: null,
        emailVerificationExpires: null,
      },
    });
  }

  async resendVerification(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new BadRequestException('Unable to resend verification for this email');
    }

    if (user.emailVerified) {
      return;
    }

    const token = this.tokenService.createEmailVerificationToken();
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerificationToken: token.hashedToken,
        emailVerificationExpires: token.expiresAt,
      },
    });

    await this.emailService.sendVerificationEmail(user.email, token.token);
  }

  async forgotPassword(dto: ForgotPasswordDto): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (!user) {
      return;
    }

    const token = this.tokenService.createPasswordResetToken();
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        resetPasswordToken: token.hashedToken,
        resetPasswordExpires: token.expiresAt,
      },
    });

    await this.emailService.sendPasswordResetEmail(user.email, token.token);
  }

  async resetPassword(dto: ResetPasswordDto): Promise<void> {
    const hashed = createHash('sha256').update(dto.token).digest('hex');
    const user = await this.prisma.user.findFirst({
      where: {
        resetPasswordToken: hashed,
        resetPasswordExpires: {
          gt: new Date(),
        },
      },
      include: {
        passwordHistories: {
          orderBy: { createdAt: 'desc' },
          take: this.passwordHistoryLimit,
        },
      },
    });

    if (!user) {
      throw new BadRequestException('Reset token is invalid or expired');
    }

    const saltRounds = this.configService.get<number>('security.bcryptRounds', 12);
    const newHash = await hash(dto.newPassword, saltRounds);

    const reused = user.passwordHistories.some((history) => history.password === newHash);
    if (reused) {
      throw new BadRequestException('Password must not match the last used passwords');
    }

    const historyCreate: Prisma.PasswordHistoryCreateWithoutUserInput = {
      password: newHash,
    };

    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: user.id },
        data: {
          password: newHash,
          resetPasswordToken: null,
          resetPasswordExpires: null,
        },
      });

      await tx.passwordHistory.create({
        data: {
          userId: user.id,
          ...historyCreate,
        },
      });

      const redundant = await tx.passwordHistory.findMany({
        where: { userId: user.id },
        orderBy: { createdAt: 'desc' },
        skip: this.passwordHistoryLimit,
        select: { id: true },
      });

      if (redundant.length) {
        await tx.passwordHistory.deleteMany({
          where: {
            id: {
              in: redundant.map((history) => history.id),
            },
          },
        });
      }
    });
  }

  async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    const hashed = createHash('sha256').update(refreshToken).digest('hex');
    const session = await this.prisma.session.findFirst({
      where: {
        refreshToken: hashed,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: true,
      },
    });

    if (!session || !session.user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    await this.prisma.session.delete({ where: { id: session.id } });

    const tokens = await this.createSession(session.user, {
      ipAddress: session.ipAddress ?? undefined,
      userAgent: session.userAgent ?? undefined,
    });

    return tokens;
  }

  async logout(sessionId: string): Promise<void> {
    await this.prisma.session.delete({ where: { id: sessionId } }).catch((error) => {
      this.logger.warn(`Attempted logout on missing session ${sessionId}: ${error}`);
    });
  }

  async getProfile(userId: string): Promise<SafeUser> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException();
    }
    return this.sanitizeUser(user);
  }

  async updateProfile(userId: string, data: Partial<Pick<User, 'name' | 'address'>>): Promise<SafeUser> {
    const user = await this.prisma.user.update({
      where: { id: userId },
      data,
    });
    return this.sanitizeUser(user);
  }

  private async createSession(user: User, context: { ipAddress?: string; userAgent?: string }): Promise<AuthTokens> {
    const sessionId = randomUUID();
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      sessionId,
    };

    const accessSecret = this.configService.get<string>('jwt.secret');
    const refreshConfig = this.tokenService.createRefreshToken();

    const { raw: accessExpiresIn, ms: accessExpiresMs } = this.resolveDuration(
      this.configService.get<string>('jwt.expiration'),
      '15m' as StringValue,
    );

    const accessToken = this.jwtService.sign(payload, {
      secret: accessSecret,
      expiresIn: accessExpiresIn,
    });

    await this.prisma.session.create({
      data: {
        id: sessionId,
        userId: user.id,
        token: accessToken,
        refreshToken: refreshConfig.hashedToken,
        expiresAt: refreshConfig.expiresAt,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
      },
    });

    return {
      accessToken,
      refreshToken: refreshConfig.token,
      expiresIn: accessExpiresMs,
      refreshExpiresIn: refreshConfig.expiresAt.getTime() - Date.now(),
    };
  }

  private sanitizeUser(user: User): SafeUser {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      dateOfBirth: user.dateOfBirth,
      address: user.address,
      emailVerified: user.emailVerified,
      profilePicture: user.profilePicture,
      isActive: user.isActive,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  private async ensureUserIsOfAge(dateIso: string): Promise<void> {
    const dob = new Date(dateIso);
    if (Number.isNaN(dob.getTime())) {
      throw new BadRequestException('Invalid date of birth');
    }

    const minAge = 13;
    const ageDiff = Date.now() - dob.getTime();
    const ageDate = new Date(ageDiff);
    const calculatedAge = Math.abs(ageDate.getUTCFullYear() - 1970);

    if (calculatedAge < minAge) {
      throw new BadRequestException('User must be at least 13 years old');
    }
  }

  private ensureAccountIsActive(user: User): void {
    if (!user.isActive) {
      throw new ForbiddenException('Account disabled');
    }
  }

  private async ensureAccountIsNotLocked(user: User): Promise<void> {
    if (user.lockUntil && user.lockUntil > new Date()) {
      throw new ForbiddenException('Account temporarily locked');
    }
  }

  private async recordFailedAttempt(user: User): Promise<void> {
    const maxAttempts = this.configService.get<number>('security.loginRateLimit', 5);
    const { ms: lockDurationMs } = this.resolveDuration(
      this.configService.get<string>('security.lockDuration'),
      '30m' as StringValue,
    );
    const nextAttempts = user.failedLoginAttempts + 1;
    const updateData: Prisma.UserUpdateInput = {
      failedLoginAttempts: nextAttempts,
    };

    if (nextAttempts >= maxAttempts) {
      updateData.lockUntil = new Date(Date.now() + lockDurationMs);
      updateData.failedLoginAttempts = 0;
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: updateData,
    });
  }

  private async resetFailedAttempts(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginAttempts: 0,
        lockUntil: null,
        lastLogin: new Date(),
      },
    });
  }

  private resolveDuration(value: string | undefined, fallback: StringValue): { raw: StringValue; ms: number } {
    const raw = (value ?? fallback) as StringValue;
    const parsed = ms(raw);
    if (typeof parsed !== 'number') {
      const fallbackParsed = ms(fallback);
      if (typeof fallbackParsed !== 'number') {
        throw new Error(`Invalid duration configuration for value: ${raw}`);
      }
      return { raw: fallback, ms: fallbackParsed };
    }
    return { raw, ms: parsed };
  }
}
