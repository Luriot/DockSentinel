export class ApiError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details?: unknown;

  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export function badRequest(message: string, code = 'invalid_request'): never {
  throw new ApiError(400, code, message);
}

export function unauthorized(message = 'Authentication required'): never {
  throw new ApiError(401, 'unauthorized', message);
}

export function forbidden(message = 'Forbidden'): never {
  throw new ApiError(403, 'forbidden', message);
}

export function notFound(message = 'Not found'): never {
  throw new ApiError(404, 'not_found', message);
}

export function conflict(message: string, code = 'conflict'): never {
  throw new ApiError(409, code, message);
}


