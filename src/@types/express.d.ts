declare global {
  namespace Express {
    interface Request {
      currentUser?: {
        id: string;
        role: 'USER' | 'ADMIN' | 'MODERATOR';
        email: string;
        firstName: string;
        lastName: string;
      };
    }
  }
}

export {};
