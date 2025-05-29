# JWT Authentication Setup Guide

Create auth.module, auth.controller and auth.service files.

```bash
nest g module auth
nest g controller auth/controllers/auth --flat
nest g service auth/services/auth --flat
```

## auth.module.ts

At this point, `auth.module.ts` should look like this:

```typescript
// auth.module.ts
import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service';
import { AuthController } from './controllers/auth.controller';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
```

## auth.controller.ts

You should add two routes to the `auth.controller.ts` file: one for registration and one for login.

```typescript
// auth/controllers/auth.controller.ts
import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { AuthRequestDto, AuthResponseDto } from '../dtos';

@Controller('auth') // /auth
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up') // /auth/sign-up
  signUp(@Body() dto: AuthRequestDto): Promise<AuthResponseDto> {
    return this.authService.signUp(dto);
  }

  @Post('login') // /auth/login
  login(@Body() dto: AuthRequestDto): Promise<AuthResponseDto> {
    return this.authService.login(dto);
  }
}
```

## DTOs

From this, we'll need to create the `AuthRequestDto` and `AuthResponseDto` data transfer objects (DTOs) in a new `dtos` directory.

Before that, we'll need class-validator and class-transformer packages for DTO validation and transformation. Install them using:

```bash
yarn add -D class-validator class-transformer
```

Create two classes in `auth/dtos/auth-request.dto.ts` and `auth/dtos/auth-response.dto.ts` as well as an `index.ts` file to export them.

```typescript
// auth/dtos/auth-request.dto.ts
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthRequestDto {
  @IsEmail() // Validates that the email is in a proper format
  @IsNotEmpty() // Ensures the email field is not empty
  email: string;

  @IsString() // Validates that the password is a string
  @IsNotEmpty() // Ensures the password field is not empty
  password: string;
}

// auth/dtos/auth-response.dto.ts
export class AuthResponseDto {
  email: string;
  access_token: string;
}

// auth/dtos/index.ts
export * from './auth-request.dto';
export * from './auth-response.dto';
```

## auth.service.ts

Now, let's implement a basic version of the `AuthService` that will handle user registration and login. For now, it will simply log the request and return a mock response.

```typescript
// auth/services/auth.service.ts
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
  signUp(dto: AuthRequestDto): Promise<AuthResponseDto> {
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
  login(dto: AuthRequestDto): Promise<AuthResponseDto> {
    console.log(dto);
    return Promise.resolve({
      email: 'user.email',
      access_token: 'token',
    });
  }
}
```
