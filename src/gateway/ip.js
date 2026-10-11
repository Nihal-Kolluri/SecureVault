/**
 * IP Extraction and Anti-Spoofing Defense
 * 
 * Protects against IP spoofing attacks via manipulated X-Forwarded-For headers.
 * When trustProxy is disabled (default for direct internet connections), X-Forwarded-For
 * headers are completely ignored, and the socket peer address is strictly used.
 * When trustProxy is enabled, only requests whose socket address matches a trusted proxy
 * have their X-Forwarded-For header inspected.
 */

// Default trusted proxy addresses (e.g., localhost loopbacks)
const DEFAULT_TRUSTED_PROXIES = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];

/**
 * Normalizes an IP string (stripping IPv6-mapped IPv4 prefix).
 * @param {string} ip
 * @returns {string}
 */
function normalizeIp(ip) {
  if (!ip) return '127.0.0.1';
  let cleaned = String(ip).trim();
  if (cleaned.startsWith('::ffff:')) {
    cleaned = cleaned.slice(7);
  }
  return cleaned;
}

/**
 * Determines whether a given IP is trusted as a proxy.
 * @param {string} ip
 * @param {boolean|string[]} trustProxy
 * @returns {boolean}
 */
function isTrustedProxy(ip, trustProxy) {
  if (trustProxy === true) {
    return true;
  }
  if (Array.isArray(trustProxy)) {
    return trustProxy.map(normalizeIp).includes(normalizeIp(ip));
  }
  return false;
}

/**
 * Extracts client IP with anti-spoofing defense.
 * @param {import('express').Request} req
 * @param {object} [options]
 * @param {boolean|string[]} [options.trustProxy=false]
 * @returns {string} Real client IP
 */
function getClientIp(req, options = {}) {
  // Read config from options, request, or environment
  const trustProxy = options.trustProxy !== undefined 
    ? options.trustProxy 
    : (req.app && req.app.get('trust proxy')) || process.env.TRUST_PROXY === 'true';

  const socketIp = normalizeIp(req.socket ? req.socket.remoteAddress : req.connection.remoteAddress);

  // If we do not trust proxies, STRICTLY return socket IP (ignore any spoofed X-Forwarded-For)
  if (!trustProxy) {
    return socketIp;
  }

  // If trustProxy is enabled, verify the immediate socket peer is trusted
  if (trustProxy !== true && !isTrustedProxy(socketIp, trustProxy)) {
    // Immediate peer is not in trusted list, so its X-Forwarded-For cannot be trusted!
    return socketIp;
  }

  const xForwardedFor = req.headers['x-forwarded-for'];
  if (!xForwardedFor) {
    return socketIp;
  }

  // Parse chain of IPs in X-Forwarded-For: "client, proxy1, proxy2"
  const rawIps = String(xForwardedFor)
    .split(',')
    .map((ip) => normalizeIp(ip))
    .filter((ip) => ip.length > 0);

  if (rawIps.length === 0) {
    return socketIp;
  }

  // If trustProxy is boolean true, the leftmost IP represents the original client
  if (trustProxy === true) {
    return rawIps[0];
  }

  // If trusted proxies list is provided, scan right-to-left to find first untrusted IP
  const trustedList = Array.isArray(trustProxy) ? trustProxy : DEFAULT_TRUSTED_PROXIES;
  for (let i = rawIps.length - 1; i >= 0; i--) {
    if (!isTrustedProxy(rawIps[i], trustedList)) {
      return rawIps[i];
    }
  }

  return rawIps[0];
}

module.exports = {
  normalizeIp,
  isTrustedProxy,
  getClientIp,
  DEFAULT_TRUSTED_PROXIES
};
