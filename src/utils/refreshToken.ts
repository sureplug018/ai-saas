import { Request, Response } from 'express';
import { BadRequestException } from '@nestjs/common';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { prisma } from 'src/lib/prisma';
import { handleCookies } from './helper.utils';

interface UserPayload {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
}

export async function generateRefreshToken(
  user: UserPayload,
  req: Request,
  res: Response,
) {
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
  handleCookies.setRefreshCookies(refreshTokenPlain, res);

  return refreshTokenPlain;
}
