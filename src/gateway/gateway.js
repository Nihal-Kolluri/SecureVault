const crypto = require('crypto');
const { getClientIp } = require('./ip');

/**
 * Creates the Gateway middleware stack.
 * @param {object} [options]
 * @param {boolean|string[]} [options.trustProxy=false]
 * @returns {import('express').RequestHandler}
 */
function createGatewayMiddleware(options = {}) {
  return function gatewayMiddleware(req, res, next) {
    // 1. Request ID tracing
    const existingId = req.headers['x-request-id'];
    const requestId = existingId && typeof existingId === 'string' && existingId.length < 128
      ? existingId
      : crypto.randomUUID();

    req.id = requestId;
    res.setHeader('X-Request-Id', requestId);

    // 2. IP extraction with anti-spoofing
    req.clientIp = getClientIp(req, options);

    // 3. Security headers (defense in depth)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"
    );

    next();
  };
}

module.exports = {
  createGatewayMiddleware
};
