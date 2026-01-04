import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { AuthGuard } from 'src/common/guard/auth.guard';
import { TokenModule } from 'src/common/module/token/token.module';

@Module({
  imports: [TokenModule],
  controllers: [UserController],
  providers: [UserService, AuthGuard],
  exports: [UserService],
})
export class UserModule {}
