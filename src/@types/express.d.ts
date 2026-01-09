import { Role } from '../lib/prisma';

declare global {
  namespace Express {
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
}

export {};
