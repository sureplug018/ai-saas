import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { GetUserByIdDto } from './dto/get-user-by-id.dto';
import { AuthGuard } from 'src/common/guard/auth.guard';
import { RolesGuard } from 'src/common/guard/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import type { CurrentUserType } from 'src/common/decorators/current-user.decorator';
import { Role } from '../../lib/prisma';

@Controller('user')
@UseGuards(AuthGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('get-user-by-id/:id')
  getUserById(@Param() dto: GetUserByIdDto) {
    return this.userService.getUserById(dto);
  }

  // test auth and roles guard
  @Get('current-user')
  @UseGuards(RolesGuard)
  @Roles(Role.USER)
  getCurrentUser(@CurrentUser() user: CurrentUserType) {
    return {
      message: 'Welcome',
      user,
    };
  }
}
