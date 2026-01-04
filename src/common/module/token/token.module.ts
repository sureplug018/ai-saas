import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TokenService } from './token.service';
import { ENVIRONMENT } from '../../constants/environment.constant';
import { CookieModule } from '../cookie/cookie.module';

@Module({
  imports: [
    CookieModule,
    JwtModule.register({
      secret: ENVIRONMENT.JWT_SECRET,
      signOptions: { expiresIn: '15m' },
    }),
  ],
  providers: [TokenService],
  exports: [TokenService], // 🔑 export so it can be used elsewhere
})
export class TokenModule {}
