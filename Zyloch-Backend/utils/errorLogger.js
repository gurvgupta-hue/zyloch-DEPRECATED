const fs = require('fs');
const path = require('path');

const logDirectory = path.join(__dirname, '../logs');
const logFilePath = path.join(logDirectory, 'error.log');

/**
 * Logs error details into a file with timestamp and request info.
 * @param {Error|string} error - Error object or message to log.
 * @param {Object} [req] - Express request object (optional).
 */
function logError(error, req) {
  const timeStamp = new Date().toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    hour12: false
  });

  const requestInfo = req
    ? `URL: ${req.originalUrl} | Method: ${req.method} | IP: ${req.ip}`
    : 'Request Info: N/A';

  const errorMessage = error instanceof Error ? error.stack : String(error);

  const logMessage = [
    `==================== ERROR LOG ====================`,
    `Time (IST): ${timeStamp}`,
    requestInfo,
    `Error: ${errorMessage}`,
    `===================================================\n`
  ].join('\n');

  try {
    // Ensure logs directory exists
    if (!fs.existsSync(logDirectory)) {
      fs.mkdirSync(logDirectory, { recursive: true });
    }

    // Append the log message
    fs.appendFileSync(logFilePath, logMessage, 'utf8');
  } catch (err) {
    console.error('❌ Failed to write error to log file:', err);
  }
}

module.exports = logError;
