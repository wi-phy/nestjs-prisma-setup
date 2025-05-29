import { Injectable } from '@nestjs/common';
import { AuthRequestDto, AuthResponseDto } from '../dtos';

@Injectable()
export class AuthService {
  constructor() {}

  /**
   * Registers a new user.
   *
   * @param dto - The DTO containing the user's email and password.
   * @returns - A promise that resolves with an object containing the JWT token (`access_token`).
   */
  async signUp(dto: AuthRequestDto): Promise<AuthResponseDto> {
    console.log(dto);
    return Promise.resolve({
      email: 'user.email',
      access_token: 'token',
    });
  }

  /**
   * Authenticates a user and returns a JWT token if the credentials are valid.
   *
   * @param dto - The DTO containing the user's email and password.
   * @returns - A promise that resolves with an object containing the JWT token (`access_token`).
   */
  async login(dto: AuthRequestDto): Promise<AuthResponseDto> {
    console.log(dto);
    return Promise.resolve({
      email: 'user.email',
      access_token: 'token',
    });
  }
}
