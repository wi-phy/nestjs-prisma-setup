# Auth feature

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

# JWT Passport Authentication

The idea behind JWT Passport authentication is to use JSON Web Tokens (JWT) to securely transmit information between parties. In this case, we will use JWT to authenticate users in our NestJS application.

It works as follows:

1. Client → Send a request to the server with `Authorization: Bearer <token>`
2. Guard → Activate the JWT strategy
3. Strategy → Validate the token with the secret from `.env` file
4. validate() → Check the user in the database via `PrismaService`

First, we need to install the necessary packages for JWT authentication:

```bash
yarn add @nestjs/jwt @nestjs/passport passport passport-jwt bcrypt
yarn add -D @types/passport-jwt @types/bcrypt
```

## jwt.strategy.ts

Next step is to create a `jwt.strategy.ts` file in the `auth/strategy` directory to handle JWT validation and export it in an `index.ts` file.

```typescript
// auth/strategy/jwt.strategy.ts

import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
// We need to extend the PassportStrategy class with the JWT strategy and give it the name 'jwt'.
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
  ) {
    // Retrieve the JWT secret environment variable from the configuration service
    const jwtSecret = configService.get('JWT_SECRET') as string;
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in environment variables');
    }

    // Configure the JWT strategy to extract the token from the Authorization header
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtSecret,
    });
  }

  /**
   * Validates the JWT payload and retrieves the user from the database.
   *
   * @param payload - The JWT payload containing user information.
   * @returns - The user object if found, or null if not found.
   */
  async validate(payload: { sub: number; email: string }) {
    const user = await this.prismaService.user.findUnique({
      where: { id: payload.sub },
    });
    return user;
  }
}

// auth/strategy/index.ts

export * from './jwt.strategy';
```

## jwt.guard.ts

Next, we need to create a JWT guard that will use the JWT strategy to protect our routes. Create a `jwt.guard.ts` file in the `auth/guards` directory and export it in an `index.ts` file.

```typescript
// auth/guards/jwt.guard.ts

import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}

// auth/guards/index.ts
export * from './jwt.guard';
```

## auth.module.ts

Now, we need to update the `auth.module.ts` file to include the JWT strategy and guard, as well as the Prisma service.

```typescript
// auth.module.ts

import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UsersModule } from 'src/users/users.module';
import { JwtStrategy } from './strategy';
import { AuthService } from './services';
import { AuthController } from './controllers';

@Module({
  // Import the JwtModule with an empty configuration
  imports: [JwtModule.register({}), UsersModule],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy], // Register the JwtStrategy as a provider
})
export class AuthModule {}
```

## auth.service.ts

Now, we need to update the `AuthService` to use the JWT module for signing tokens and to hash passwords using bcrypt.

```typescript
// auth/services/auth.service.ts

import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/services';
import { AuthRequestDto, AuthResponseDto } from '../dtos';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Registers a new user.
   *
   * This method takes user credentials (email and password), hashes the password using bcrypt,
   * and creates a new user record in the database.  It returns the user data without the password hash.
   *
   * @param {AuthDto} dto - The DTO containing the user's email and password.
   * @returns {Promise<AuthResponseDto>} - A promise that resolves to the newly created user object (without the hash).
   */
  async signUp(dto: AuthRequestDto): Promise<AuthResponseDto> {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(dto.password, salt);

    try {
      const { id, email } = await this.usersService.createUser(dto.email, hash);

      const token = await this.signToken(id, email);
      return {
        email,
        access_token: token,
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Email already exists');
        }
      }
      throw error;
    }
  }

  /**
   * Authenticates a user and returns a JWT token if the credentials are valid.
   *
   * @param {AuthDto} dto - The DTO containing the user's email and password.
   * @returns {Promise<AuthResponseDto>} - A promise that resolves with an object containing the JWT token (`access_token`).
   */
  async login(dto: AuthRequestDto): Promise<AuthResponseDto> {
    const user = await this.usersService.getUserByEmail(dto.email);
    if (!user || !user.hash)
      throw new ForbiddenException('Invalid credentials');

    const isPasswordValid = await bcrypt.compare(dto.password, user.hash);
    if (!isPasswordValid) throw new ForbiddenException('Invalid credentials');

    const token = await this.signToken(user.id, user.email);
    return {
      email: user.email,
      access_token: token,
    };
  }

  /**
   * Sign a JWT token with the user id and email
   *
   * @param {number} userId - The ID of the user.
   * @param {string} email - The email address of the user.
   * @returns {Promise<string>} - A promise that resolves with the JWT (`access_token`).
   */
  private async signToken(userId: number, email: string): Promise<string> {
    const payload = {
      sub: userId,
      email,
    };

    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '30m',
      secret: this.configService.get('JWT_SECRET'),
    });

    return token;
  }
}
```

# Users feature

Previously, we updated the `AuthService` to use a `UsersService` for user management. Now, we need to create the `UsersModule` and `UsersService`.

```bash
nest g module users
nest g service users/services/users --flat
```

## users.module.ts

```typescript
// users/users.module.ts

import { Module } from '@nestjs/common';
import { UsersService } from './services';

@Module({
  controllers: [],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
```

## users.service.ts

```typescript
// users/services/users.service.ts

import { Injectable, NotFoundException } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Creates a new user in the database.
   *
   * @param {string} email - The email address of the new user.
   * @param {string} hash - The hashed password of the new user.
   * @returns {Promise<Omit<User, 'hash'>>} A Promise that resolves to the user object without hash.
   */
  async createUser(email: string, hash: string): Promise<Omit<User, 'hash'>> {
    return await this.prismaService.user.create({
      data: { email, hash },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  /**
   * Retrieves a user by their email.
   *
   * @param {string} email - The email of the user to retrieve.
   * @returns {Promise<User>} - A promise that resolves to the user object.
   */
  async getUserByEmail(email: string): Promise<User> {
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (!user) throw new NotFoundException('No user match this id');

    return user;
  }
}
```
