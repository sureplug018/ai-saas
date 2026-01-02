import { Response } from 'express';

interface CookieOptions {
  maxAge?: number;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: boolean | 'lax' | 'strict' | 'none';
}

export const BaseHelper = {
  // Other helper methods...

  setCookie(
    response: Response,
    name: string,
    value: string,
    options: CookieOptions,
  ) {
    response.cookie(name, value, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      ...options,
    });
  },

  deleteAuthTokenCookie(response: Response) {
    response.clearCookie('access-token');
    response.clearCookie('refresh-token');
  },

  // Other helper methods...
};
