/**
 * Validation utilities for input sanitization and security
 */

const createError = require("./createError");

/**
 * Validates that a value is a positive integer
 * @param {any} value - Value to validate
 * @param {string} fieldName - Name of the field for error messages
 * @returns {number} Validated integer
 * @throws {Error} If validation fails
 */
function validatePositiveInteger(value, fieldName = "ID") {
  const parsed = Number(value);
  
  if (isNaN(parsed) || !Number.isInteger(parsed) || parsed <= 0) {
    throw createError(400, `Invalid ${fieldName}: must be a positive integer`);
  }
  
  return parsed;
}

/**
 * Validates that a string is not empty and is a valid ObjectId-like format
 * @param {any} value - Value to validate
 * @param {string} fieldName - Name of the field for error messages
 * @returns {string} Validated string
 * @throws {Error} If validation fails
 */
function validateMongoId(value, fieldName = "ID") {
  if (!value || typeof value !== 'string' || !/^[a-f\d]{24}$/i.test(value)) {
    throw createError(400, `Invalid ${fieldName}: must be a valid MongoDB ID`);
  }
  
  return value;
}

/**
 * Validates that a string exists and is not empty
 * @param {any} value - Value to validate
 * @param {string} fieldName - Name of the field for error messages
 * @returns {string} Validated string
 * @throws {Error} If validation fails
 */
function validateNonEmptyString(value, fieldName = "value") {
  if (!value || typeof value !== 'string' || value.trim().length === 0) {
    throw createError(400, `Invalid ${fieldName}: must be a non-empty string`);
  }
  
  return value.trim();
}

function getOAuthCallbackUrl(provider, configuredRedirectUri) {
  if (!['google', 'microsoft'].includes(provider)) {
    throw createError(400, 'Invalid OAuth provider');
  }

  const publicBackendUrl = process.env.OAUTH_REDIRECT_URI || configuredRedirectUri;
  if (!publicBackendUrl) {
    throw createError(500, 'OAuth backend URL is not configured');
  }

  try {
    return new URL(`/auth/${provider}/callback`, publicBackendUrl).toString();
  } catch {
    throw createError(400, 'Invalid OAuth redirect URI');
  }
}

function validateOAuthCallbackUrl(redirectUri, provider) {
  const expectedRedirectUri = getOAuthCallbackUrl(provider, redirectUri);

  if (redirectUri !== expectedRedirectUri) {
    throw createError(
      400,
      `Invalid ${provider} redirect URI. Use ${expectedRedirectUri}`,
    );
  }

  return expectedRedirectUri;
}

module.exports = {
  validatePositiveInteger,
  validateMongoId,
  validateNonEmptyString,
  getOAuthCallbackUrl,
  validateOAuthCallbackUrl,
};
