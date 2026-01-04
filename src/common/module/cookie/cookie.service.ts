import { Injectable } from '@nestjs/common';
import { Response, Request } from 'express';
import crypto from 'crypto';
import { prisma } from 'src/lib/prisma';

@Injectable()
export class CookieService {
  setAccessCookies(token: string, res: Response) {
    res.cookie('accessToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 15 * 60 * 1000,
    });
  }

  setRefreshCookies(refreshTokenPlain: string, res: Response) {
    res.cookie('refreshToken', refreshTokenPlain, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }

  async deleteCookies(res: Response, req: Request, userId: string) {
    res.clearCookie('accessToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
    });

    const cookies = req.cookies as { refreshToken?: string };

    const refreshToken = cookies.refreshToken;
    if (!refreshToken) return;

    const lookupHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    await prisma.refreshToken.delete({
      where: {
        userId,
        lookupHash,
      },
    });

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
    });
  }
}
