import { Role } from '../../lib/prisma';

declare module 'express-serve-static-core' {
  interface Request {
    currentUser?: {
      id: string;
      role: Role;
      email: string;
      firstName: string;
      lastName: string;
    };
  }
}
