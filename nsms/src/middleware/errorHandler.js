// src/middleware/errorHandler.js
/**
 * Functional error handling middleware for Express.
 * It expects error objects to optionally contain a `status` property.
 */
function errorHandler(err, req, res, next) {
  // If headers already sent, delegate to default Express handler
  if (res.headersSent) {
    return next(err);
  }
  const status = err.status || 500;
  const response = {
    status,
    message: err.message || 'Internal Server Error',
  };
  // Include stack trace only in development
  if (process.env.NODE_ENV !== 'production' && err.stack) {
    response.stack = err.stack;
  }
  res.status(status).json(response);
}

module.exports = { errorHandler };
