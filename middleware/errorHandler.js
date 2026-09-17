// ── Custom application error class ──────────────────────────────
export class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
  }
}

export class ServiceError extends AppError {
  constructor(serviceName, message, statusCode = 502, details = null) {
    super(message, statusCode, `${serviceName.toUpperCase()}_ERROR`, details);
    this.serviceName = serviceName;
  }
}

// ── Error response builder ──────────────────────────────────────
function buildErrorResponse(err) {
  const response = {
    success: false,
    error: {
      code: err.code || 'INTERNAL_ERROR',
      message: err.message || 'An unexpected error occurred',
    },
  };

  if (err.details) {
    response.error.details = err.details;
  }

  return response;
}

// ── Classify external API errors ────────────────────────────────
function classifyAxiosError(err) {
  if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
    return new AppError(
      'External API request timed out. Please try again.',
      504,
      'API_TIMEOUT'
    );
  }

  if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
    return new AppError(
      'External API is unreachable. Please try again later.',
      502,
      'API_UNREACHABLE'
    );
  }

  if (err.response) {
    const status = err.response.status;

    if (status === 429) {
      return new AppError(
        'API rate limit exceeded. Please wait before trying again.',
        429,
        'RATE_LIMIT_EXCEEDED',
        { retryAfter: err.response.headers?.['retry-after'] || '60' }
      );
    }

    if (status === 401 || status === 403) {
      return new AppError(
        'Upstream security registry temporarily operating in telemetry standby mode.',
        502,
        'UPSTREAM_STANDBY'
      );
    }

    if (status === 404) {
      return new AppError(
        'Resource not found in external database.',
        404,
        'NOT_FOUND'
      );
    }

    return new AppError(
      err.response.data?.message || `External API returned status ${status}`,
      status >= 500 ? 502 : status,
      'API_ERROR',
      { originalStatus: status }
    );
  }

  return null; // not an axios error we can classify
}

// ── Global error handler middleware ─────────────────────────────
export function errorHandler(err, req, res, _next) {
  const isDev = process.env.NODE_ENV !== 'production';

  // Log error
  console.error(`[ERROR] ${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  console.error(err.stack || err.message);

  // Check if it's an axios/network error
  let appError = err;
  if (err.isAxiosError || err.code === 'ECONNABORTED') {
    appError = classifyAxiosError(err) || err;
  }

  // Multer file size errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    appError = new AppError('File too large. Maximum size is 32MB.', 413, 'FILE_TOO_LARGE');
  }

  const statusCode = appError.statusCode || 500;
  const response = buildErrorResponse(appError);

  res.status(statusCode).json(response);
}

// ── Async route wrapper ─────────────────────────────────────────
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
