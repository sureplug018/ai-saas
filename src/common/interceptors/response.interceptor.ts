import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, map } from 'rxjs';
import { Response as ExpressResponse } from 'express';
import { ResponseMessageKey } from '../decorators/response.decorator';

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  message: string | null;
  successCode: number;
  [key: string]: any;
}

@Injectable()
export class ResponseTransformerInterceptor<T> implements NestInterceptor<
  T,
  ApiResponse<T>
> {
  constructor(private reflector: Reflector) {}

  intercept(
    context: ExecutionContext,
    next: CallHandler<T>,
  ): Observable<ApiResponse<T>> {
    const response = context.switchToHttp().getResponse<ExpressResponse>(); // 👈 properly typed

    const responseMessage =
      this.reflector.get<string>(ResponseMessageKey, context.getHandler()) ??
      null;

    return next.handle().pipe(
      map((data: T) => {
        const statusCode = response.statusCode; // 👈 now typed (number)

        return {
          success: statusCode === 200 || statusCode === 201,
          data, // 👈 typed from T
          message: responseMessage || 'Request successful',
          successCode: statusCode,
        };
      }),
    );
  }
}
