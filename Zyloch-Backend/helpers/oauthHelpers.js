/**
 * OAuth Helper Functions
 * Token refresh utilities for Google and Microsoft OAuth
 * 
 * Note: With Passport.js, most OAuth logic (authorization, token exchange, user info)
 * is handled automatically by the strategies. This file now only contains token refresh logic.
 */

const axios = require('axios');

/**
 * Refresh access token using refresh token (Google)
 */
async function refreshGoogleToken(refreshToken, config) {
  try {
    const response = await axios.post(config.tokenURL, {
      refresh_token: refreshToken,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'refresh_token',
    }, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    return response.data;
  } catch (error) {
    console.error('Google token refresh error:', error.response?.data || error.message);
    throw new Error('Failed to refresh Google access token');
  }
}

/**
 * Refresh access token using refresh token (Microsoft)
 */
async function refreshMicrosoftToken(refreshToken, config) {
  try {
    const params = new URLSearchParams({
      refresh_token: refreshToken,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'refresh_token',
      scope: config.scope,
    });

    const response = await axios.post(config.tokenURL, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    return response.data;
  } catch (error) {
    console.error('Microsoft token refresh error:', error.response?.data || error.message);
    throw new Error('Failed to refresh Microsoft access token');
  }
}

module.exports = {
  refreshGoogleToken,
  refreshMicrosoftToken,
};
