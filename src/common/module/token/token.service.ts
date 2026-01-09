import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { prisma } from 'src/lib/prisma';
import { CookieService } from 'src/common/module/cookie/cookie.service';
import { Role } from '../../../lib/prisma';

interface User {
  id: string;
  email: string;
  role: Role;
  firstName: string;
  lastName: string;
}

interface UserPayload {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
}

export interface AccessTokenPayload {
  userId: string; // user id
  email: string;
  role: Role;
  firstName: string;
  lastName: string;
}

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly cookieService: CookieService,
  ) {}

  signAccessToken(user: User, res: Response): string {
    const payload = {
      email: user.email,
      userId: user.id,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
    };
    const token = this.jwtService.sign(payload);

    // set cookie
    this.cookieService.setAccessCookies(token, res);

    return token;
  }

  //generate refresh token here
  async generateRefreshToken(user: UserPayload, req: Request, res: Response) {
    const refreshTokenPlain = crypto.randomBytes(64).toString('hex');
    const refreshTokenHash = await bcrypt.hash(refreshTokenPlain, 12);
    const lookupHash = crypto
      .createHash('sha256')
      .update(refreshTokenPlain)
      .digest('hex');

    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];

    if (!ipAddress || !userAgent) {
      throw new BadRequestException('Cannot determine client information');
    }

    await prisma.refreshToken.create({
      data: {
        tokenHash: refreshTokenHash,
        lookupHash,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 30 days
        ipAddress,
        userAgent,
      },
    });

    // Set refresh token as HttpOnly cookie
    this.cookieService.setRefreshCookies(refreshTokenPlain, res);

    return refreshTokenPlain;
  }

  verifyAccessToken(
    accessToken: string,
    jwtSecret: string,
  ): AccessTokenPayload {
    return this.jwtService.verify<AccessTokenPayload>(accessToken, {
      secret: jwtSecret,
    });
  }

  async verifyRefreshToken(refreshToken: string) {
    const lookupHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const tokenRecord = await prisma.refreshToken.findUnique({
      where: { lookupHash },
      include: { user: true },
    });

    // 1️⃣ Token not found → reuse attack
    if (!tokenRecord) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // 2️⃣ Revoked or expired
    if (tokenRecord.revokedAt || tokenRecord.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token expired or revoked');
    }

    // 3️⃣ Compare token securely
    const isValid = await bcrypt.compare(refreshToken, tokenRecord.tokenHash);

    // 4️⃣ Hash mismatch → reuse attack
    if (!isValid) {
      await prisma.refreshToken.updateMany({
        where: { userId: tokenRecord.userId },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    // 5️⃣ Rotate token → delete used one
    await prisma.refreshToken.delete({
      where: { id: tokenRecord.id },
    });

    return tokenRecord;
  }
}
