import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ERROR_CONSTANT } from '../constants/error.constant';
import {
  NotBeforeError,
  TokenExpiredError,
  JsonWebTokenError,
} from '@nestjs/jwt';
import { ENVIRONMENT } from '../constants/environment.constant';
import { prisma } from 'src/lib/prisma';
import crypto from 'crypto';
import { TokenService } from '../module/token/token.service';

interface customRequest extends Request {
  currentUser?: {
    id: string;
    role: string; // or your Role type
    firstName: string;
    lastName: string;
    email: string;
  };
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly tokenService: TokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: customRequest = context.switchToHttp().getRequest();
    const response: Response = context.switchToHttp().getResponse();

    const accessToken = request.cookies?.['accessToken'] as string;
    const refreshToken = request.cookies?.['refreshToken'] as string;

    if (!refreshToken)
      throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);

    try {
      if (!accessToken) {
        // verify refresh token
        const lookupHash = crypto
          .createHash('sha256')
          .update(refreshToken)
          .digest('hex');

        const refreshTokenRecord = await prisma.refreshToken.findUnique({
          where: { lookupHash },
          include: { user: true },
        });
        if (refreshTokenRecord) {
          const { id, role, firstName, lastName, email } =
            refreshTokenRecord.user;
          await this.tokenService.verifyRefreshToken(refreshToken, id);
          // if fresh token is valid, generate access token
          this.tokenService.signAccessToken(refreshTokenRecord.user, response);
          // set current user in the request object
          request.currentUser = { id, role, firstName, lastName, email };
        }
        return true;
      } else {
        // if there is access token, verify the access token

        this.tokenService.verifyAccessToken(
          accessToken,
          ENVIRONMENT.JWT_SECRET,
        );
        // if valid set current user in the request object
        return true;
      }
    } catch (err) {
      if (err instanceof JsonWebTokenError)
        throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);

      // if access is expired and there is refresh token

      if (err instanceof TokenExpiredError && refreshToken) {
        // check the validity of the refresh token
        // if still valid, assign a new access token
      } else {
        throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);
      }

      if (err instanceof NotBeforeError)
        throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);

      throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);
    }
  }
}
