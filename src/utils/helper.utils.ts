import { Response } from 'express';
import { prisma } from 'src/lib/prisma';
import crypto from 'crypto';
import type { Request } from 'express';

export const handleCookies = {
  // set cookie expiration to 15 minutes
  setAccessCookies(token: string, res: Response) {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none' as const,
      maxAge: 15 * 60 * 1000, // 15 minutes in milliseconds
    };

    res.cookie('accessToken', token, cookieOptions);
  },

  // Set refresh token as HttpOnly cookie
  setRefreshCookies(refreshTokenPlain: string, res: Response) {
    res.cookie('refreshToken', refreshTokenPlain, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
  },

  async deleteCookies(res: Response, req: Request, id: string) {
    res.clearCookie('accessToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
    });

    const refreshToken = typeof req.cookies['refreshToken'];

    if (refreshToken) {
      const lookupHash = crypto
        .createHash('sha256')
        .update(refreshToken)
        .digest('hex');

      // delete all refresh tokens from the user agent
      await prisma.refreshToken.delete({
        where: {
          userId: id,
          lookupHash,
        },
      });
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'none',
      });
    }
  },
};
