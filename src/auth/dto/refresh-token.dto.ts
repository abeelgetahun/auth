import { IsString, Length } from 'class-validator';

export class RefreshTokenDto {
  @IsString()
  @Length(10, 256)
  refreshToken!: string;
}
