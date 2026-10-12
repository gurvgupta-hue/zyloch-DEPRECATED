const axios = require('axios');
const createError = require('../utils/createError');

const SERVICE_KEY_HEADER = 'X-Zyloch-Service-Key';

function getGhappBaseUrl() {
  const base =
    process.env.SCAN_API_URL ||
    process.env.NEXT_PUBLIC_SCAN_API_URL ||
    'http://policy-scanner:8000';
  return String(base).replace(/\/$/, '');
}

function getGhappHeaders(extraHeaders = {}) {
  const apiKey = process.env.GHAPP_S2S_API_KEY;
  if (!apiKey) {
    throw createError(500, 'GHAPP service credentials are not configured');
  }

  return {
    'Content-Type': 'application/json',
    [SERVICE_KEY_HEADER]: apiKey,
    ...extraHeaders,
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Errors that prove the request never reached GHAPP, so replaying it cannot
 * duplicate a side effect (safe to retry even for POST /scan). Errors like
 * ECONNRESET/ETIMEDOUT are deliberately excluded: the request may already
 * have been processed, and retrying could trigger a second scan.
 */
const RETRYABLE_CONNECT_CODES = new Set(['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN']);

const CONNECT_RETRIES = 4;
const CONNECT_RETRY_DELAY_MS = 1500;

/**
 * Call GHAPP with service-to-service credentials.
 *
 * GHAPP takes ~50s from container start to accept connections, during which
 * every call fails with ECONNREFUSED. Connection-level failures are retried
 * with backoff so a restart/deploy does not surface as a user-facing error.
 *
 * @param {'GET'|'POST'|'PUT'|'DELETE'} method
 * @param {string} path
 * @param {{ params?: object, data?: object, timeout?: number }} [options]
 */
async function ghappRequest(method, path, options = {}) {
  const { params, data, timeout = 120000 } = options;
  const url = `${getGhappBaseUrl()}${path}`;

  let lastConnectErr;

  for (let attempt = 0; attempt <= CONNECT_RETRIES; attempt++) {
    try {
      const response = await axios({
        method,
        url,
        params,
        data,
        headers: getGhappHeaders(),
        timeout,
        validateStatus: () => true,
      });

      if (response.status >= 400) {
        const detail =
          response.data?.detail ||
          response.data?.message ||
          response.statusText ||
          'GHAPP request failed';
        const message = typeof detail === 'string' ? detail : JSON.stringify(detail);
        throw createError(response.status, message);
      }

      return response.data;
    } catch (err) {
      if (err.statusCode) {
        throw err;
      }

      if (!RETRYABLE_CONNECT_CODES.has(err.code) || attempt === CONNECT_RETRIES) {
        throw createError(502, `GHAPP request failed: ${err.message}`);
      }

      lastConnectErr = err;
      console.warn(
        `[ghapp] ${err.code} reaching ${url} (attempt ${attempt + 1}/${CONNECT_RETRIES + 1}); retrying in ${CONNECT_RETRY_DELAY_MS}ms`
      );
      await sleep(CONNECT_RETRY_DELAY_MS);
    }
  }

  throw createError(502, `GHAPP request failed: ${lastConnectErr?.message}`);
}

module.exports = {
  SERVICE_KEY_HEADER,
  getGhappBaseUrl,
  getGhappHeaders,
  ghappRequest,
};
