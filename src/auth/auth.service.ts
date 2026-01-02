import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SigninDto } from './dto/signin.dto';
import { SignupDto } from './dto/signup.dto';
import { prisma } from '../lib/prisma';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { Request } from 'express';
import {
  checkLoginBlock,
  recordFailedLogin,
  resetLoginAttempts,
} from 'src/utils/loginAttempts';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

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

    return { message: 'User created successfully', userId: user.id };
  }

  async signin(signinDto: SigninDto, req: Request) {
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
    const payload = { email: user.email, userId: user.id, role: user.role };
    const token = this.jwtService.sign(payload);

    // generate refresh token
    const refreshTokenPlain = crypto.randomBytes(64).toString('hex');
    const refreshTokenHash = await bcrypt.hash(refreshTokenPlain, 12);
    const lookupHash = crypto
      .createHash('sha256')
      .update(refreshTokenPlain)
      .digest('hex');

    const ipAddress = req.ip;
    const userAgent = req.headers['user-agent'];

    if (!ipAddress || !userAgent) {
      throw new BadRequestException('Cannot determine client information');
    }

    await prisma.refreshToken.create({
      data: {
        tokenHash: refreshTokenHash,
        lookupHash,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 30 days
        ipAddress,
        userAgent,
      },
    });

    return { message: 'Signin successful', token, refreshTokenPlain };
  }
}
