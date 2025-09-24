import { AppError } from './AppError';

export class DatabaseError extends AppError {
  constructor(message: string, statusCode: number = 500) {
    super(message, statusCode);
  }
}

export class ConnectionError extends DatabaseError {
  constructor(message: string = 'Database connection failed') {
    super(message, 503);
  }
}

export class QueryError extends DatabaseError {
  constructor(message: string = 'Database query failed') {
    super(message, 500);
  }
}
