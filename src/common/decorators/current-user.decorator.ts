import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Role } from '../../lib/prisma';
import { Request } from 'express';

export interface CurrentUserType {
  id: string;
  email: string;
  role: Role;
  firstName: string;
  lastName: string;
}

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): CurrentUserType | undefined => {
    const request: Request = ctx.switchToHttp().getRequest();
    return request.currentUser;
  },
);
