import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { handleCookies } from 'src/utils/helper.utils';

interface User {
  id: string;
  email: string;
  role: string;
}

export function signAccessToken(
  user: User,
  jwtService: JwtService,
  res: Response,
) {
  const payload = { email: user.email, userId: user.id, role: user.role };
  const token = jwtService.sign(payload);

  handleCookies.setAccessCookies(token, res);

  return token;
}
