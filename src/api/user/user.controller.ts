import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { GetUserByIdDto } from './dto/get-user-by-id.dto';
import { AuthGuard } from 'src/common/guard/auth.guard';

@Controller('user')
@UseGuards(AuthGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('get-user-by-id/:id')
  getUserById(@Param() dto: GetUserByIdDto) {
    return this.userService.getUserById(dto);
  }
}
