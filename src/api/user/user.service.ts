import { Injectable, NotFoundException } from '@nestjs/common';
import { GetUserByIdDto } from './dto/get-user-by-id.dto';
import { prisma } from 'src/lib/prisma';

@Injectable()
export class UserService {
  async getUserById(dto: GetUserByIdDto) {
    const { id } = dto;

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        role: true,
      },
    });

    if (!user) throw new NotFoundException('User does not exist');
    return user;
  }
}
