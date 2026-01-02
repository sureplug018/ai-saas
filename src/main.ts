import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger } from '@nestjs/common';
import morgan from 'morgan';
import * as express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import hpp from 'hpp';
import { ResponseTransformerInterceptor } from './common/interceptors/response.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Nest logger instance
  const logger = new Logger('Bootstrap');
  app.useLogger(logger);

  app.use(
    morgan('dev', {
      skip: () => process.env.NODE_ENV === 'production',
      stream: {
        write: (message) => logger.log(message.trim()),
      },
    }),
  );

  app.use(helmet());
  app.use(hpp());

  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

  app.use(cookieParser());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      forbidUnknownValues: true,
    }),
  );

  //  interceptors
  app.useGlobalInterceptors(
    new ResponseTransformerInterceptor(app.get(Reflector)),
  );

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  logger.log(`Application is running on: http://localhost:${port}`);
}
bootstrap();
