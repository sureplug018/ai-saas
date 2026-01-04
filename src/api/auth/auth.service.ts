import { BadRequestException, Injectable } from '@nestjs/common';
import { SigninDto } from './dto/signin.dto';
import { SignupDto } from './dto/signup.dto';
import { prisma } from '../../lib/prisma';
import * as bcrypt from 'bcrypt';
import { Request, Response } from 'express';
import {
  checkLoginBlock,
  recordFailedLogin,
  resetLoginAttempts,
} from 'src/utils/loginAttempts';
import { TokenService } from 'src/common/module/token/token.service';

@Injectable()
export class AuthService {
  constructor(private readonly tokenService: TokenService) {}

  async signup(signupDto: SignupDto) {
    const { firstName, lastName, email, password } = signupDto;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new BadRequestException('User with this email already exists');
    }

    // salt and hash password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create the new user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstName,
        lastName,
      },
    });

    // send confirmation email

    return { message: 'User created successfully', userId: user.id };
  }

  async signin(signinDto: SigninDto, req: Request, res: Response) {
    const { email, password } = signinDto;

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        password: true,
      },
    });

    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }

    // 🔒 Check account lock to ensure brute force attack
    const block = await checkLoginBlock(user.id);
    if (block.blocked) {
      throw new BadRequestException(
        `Too many failed login attempts. Try again in ${Math.ceil(
          (block.ttl ?? 0) / 60,
        )} minutes.`,
      );
    }

    // Compare passwords and record failed login attempt if invalid
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      const attempts = await recordFailedLogin(user.id);
      const remaining = 4 - attempts;

      throw new BadRequestException(
        remaining > 0
          ? `Incorrect email or password. ${remaining} attempt(s) left.`
          : 'Too many failed login attempts. Account temporarily locked.',
      );
    }

    // ✅ Successful login → reset attempts
    await resetLoginAttempts(user.id);

    // Generate JWT token
    const token = this.tokenService.signAccessToken(user, res);

    //   Generate refresh token
    const refreshTokenPlain = await this.tokenService.generateRefreshToken(
      user,
      req,
      res,
    );

    return { message: 'Signin successful', token, refreshTokenPlain };
  }
}
