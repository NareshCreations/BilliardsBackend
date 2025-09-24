import { AppError } from './AppError';

export class AuthError extends AppError {
  constructor(message: string, statusCode: number = 401) {
    super(message, statusCode);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, statusCode: number = 400) {
    super(message, statusCode);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string = 'Resource not found', statusCode: number = 404) {
    super(message, statusCode);
  }
}

export class ConflictError extends AppError {
  constructor(message: string, statusCode: number = 409) {
    super(message, statusCode);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message: string = 'Unauthorized access', statusCode: number = 401) {
    super(message, statusCode);
  }
}

export class ForbiddenError extends AppError {
  constructor(message: string = 'Forbidden access', statusCode: number = 403) {
    super(message, statusCode);
  }
}
