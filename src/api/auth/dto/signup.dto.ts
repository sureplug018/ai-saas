import { IsEmail, IsString, MinLength } from 'class-validator';
import { MatchPassword } from 'src/validators/match-password.validator';

export class SignupDto {
  @MinLength(3)
  @IsString()
  firstName: string;

  @MinLength(3)
  @IsString()
  lastName: string;

  @IsEmail()
  email: string;

  @MinLength(8)
  @IsString()
  password: string;

  @MinLength(8)
  @IsString()
  @MatchPassword('password', { message: 'Passwords do not match' })
  confirmPassword: string;
}
