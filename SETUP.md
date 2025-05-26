# NestJS Setup Guide

Install `yarn`:

```bash
corepack enable
```

Install `@nestjs/cli` globally:

```bash
yarn add -g @nestjs/cli
```

Create a new `Nest` app:

```bash
nest new project-name
```

Generate a `Nest` component (module, controller, guard, service):

```bash
nest g module
```

Use `-d` for dry-run, `--flat` for flat structure.

Start the application:

```bash
yarn start:dev
```

Launch docker for the database:

```bash
docker compose up -d
```

# Prisma Setup

Install prisma:

```bash
yarn add prisma @prisma/client
```

Init Prisma with PostgreSQL as the datasource provider:

```bash
npx prisma init --datasource-provider postgresql --output ../generated/prisma
```

It creates a new directory called `prisma` that contains a file called `schema.prisma`. Should add generated/prisma to your `.gitignore` file.

### Create a migration

```bash
yarn prisma migrate dev --name name-of-your-migration
```

### Apply migrations

```bash
yarn prisma migrate dev
```

### Generate Prisma client (once, after creating the schema)

```bash
yarn prisma generate
```

### Prisma studio

```bash
yarn prisma studio
```

# main.ts

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS in development mode
  if (process.env.NODE_ENV === 'development') {
    app.enableCors();
  }

  /** Global validation pipe
   * This will validate incoming requests and transform them to DTOs
   * It will also strip properties that are not defined in the DTOs
   * and throw an error if any non-whitelisted properties are present
   * This is useful for security and data integrity
   */
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Swagger setup if needed
  const config = new DocumentBuilder()
    .setTitle('NestJS Gamecounter API')
    .setDescription('Base URL: http://localhost:3000')
    .addServer('http://localhost:3000')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  // Set global prefix for API routes
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
```

# app.module.ts

```typescript
import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './prisma/prisma.module';
import { SomeFeatureModule } from './games/games.module';

@Module({
  imports: [
    // Import the ConfigModule to manage environment variables
    // and make it available globally across the application.
    ConfigModule.forRoot({ isGlobal: true }),
    // AuthModule handles authentication and authorization.
    AuthModule,
    // UsersModule manages user-related operations.
    UsersModule,
    // PrismaModule provides access to the Prisma ORM for database operations.
    PrismaModule,
    // Add any feature module you want to add.
    SomeFeatureModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
```

# .env

```dotenv
JWT_SECRET=""

DATABASE_URL="postgresql://{YOUR_USER}:{YOUR_PASSWORD}@localhost:{YOUR_PORT}/{YOUR_DBNAME}?schema=public"
DB_USER=""
DB_PASSWORD=""
DB_NAME=""
DB_PORT=""
```

# docker.compose.yml

```yaml
version: '3.8'
services:
  # name-db is the service name for the PostgreSQL database
  name-db:
    image: postgres:17-alpine
    restart: always
    environment:
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME}
      PGDATA: /var/lib/postgresql/data/pgdata
    ports:
      - '${DB_PORT}:5432'
    # Mount a volume to persist database data
    volumes:
      - name-db-pgdata:/var/lib/postgresql/data/pgdata
    healthcheck:
      test:
        [
          'CMD-SHELL',
          'pg_isready -U ${DB_USER:-myuser} -d ${DB_NAME:-mydatabase}',
        ]
      interval: 10s
      timeout: 5s
      retries: 5
volumes:
  # name-db-pgdata is the volume name for PostgreSQL data persistence
  name-db-pgdata: {}
```

# Prisma Schema

```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        Int      @id @default(autoincrement())
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  email String @unique
  hash  String
  games Game[]

  @@map("users")
}

model Game {
  id        Int      @id @default(autoincrement())
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  players Player[]

  userId Int
  user   User @relation(fields: [userId], references: [id])

  @@map("games")
}

model Player {
  id Int @id @default(autoincrement())

  name  String
  score Int

  gameId Int
  game   Game @relation(fields: [gameId], references: [id])

  @@map("players")
}
```

# src/prisma

## prisma.module.ts

```typescript
import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

// This module provides the PrismaService globally, allowing it to be injected
// into any other module without needing to import it explicitly.
@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
```

## prisma.service.ts

```typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor(private readonly config: ConfigService) {
    // Initialize PrismaClient with the database URL from the ConfigService
    super({ datasources: { db: { url: config.get('DATABASE_URL') } } });
  }
}
```
