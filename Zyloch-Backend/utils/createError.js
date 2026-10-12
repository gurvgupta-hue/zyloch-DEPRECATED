/**
 * Creates a custom error object with status code and message.
 * @param {number} statusCode - HTTP status code.
 * @param {string} message - Error message.
 * @returns {Error} Custom error object.
 */  
function createError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.isOperational = true; // Mark as operational (not a programming bug)
  return error;
}

module.exports = createError; 
 