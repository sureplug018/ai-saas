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

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly tokenService: TokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    const response: Response = context.switchToHttp().getResponse();

    const accessToken = request.cookies?.['accessToken'] as string;
    const refreshToken = request.cookies?.['refreshToken'] as string;

    if (!accessToken && !refreshToken)
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
        if (
          !refreshTokenRecord ||
          refreshTokenRecord.revokedAt ||
          refreshTokenRecord.expiresAt < new Date()
        ) {
          throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);
        }
        const { id, role, firstName, lastName, email } =
          refreshTokenRecord.user;
        await this.tokenService.verifyRefreshToken(refreshToken);
        // if fresh token is valid, generate access token
        this.tokenService.signAccessToken(refreshTokenRecord.user, response);
        // set current user in the request object
        request.currentUser = { id, role, firstName, lastName, email };

        return true;
      } else {
        // if there is access token, verify the access token

        const payload = this.tokenService.verifyAccessToken(
          accessToken,
          ENVIRONMENT.JWT_SECRET,
        );
        // if valid set current user in the request object
        request.currentUser = {
          id: payload.userId,
          role: payload.role,
          email: payload.email,
          firstName: payload.firstName,
          lastName: payload.lastName,
        };
        return true;
      }
    } catch (err) {
      // check for expired access token
      if (err instanceof TokenExpiredError && refreshToken) {
        // check the validity of the refresh token
        const tokenRecord =
          await this.tokenService.verifyRefreshToken(refreshToken);
        // if still valid, assign a new access token
        this.tokenService.signAccessToken(tokenRecord.user, response);
        // grant access

        const user = tokenRecord.user;
        request.currentUser = {
          id: user.id,
          role: user.role,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        };
        return true;
      }

      if (err instanceof JsonWebTokenError || err instanceof NotBeforeError)
        throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);

      throw new UnauthorizedException(ERROR_CONSTANT.UNAUTHORIZED_ERROR);
    }
  }
}
