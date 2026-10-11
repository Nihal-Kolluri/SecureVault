const Redis = require('ioredis');
const { MemoryRedis } = require('./memory-redis');

let defaultRedisClient = null;

/**
 * Gets or initializes a shared Redis client.
 * Falls back to MemoryRedis if REDIS_URL is not provided or connection fails.
 * @returns {object} Redis client instance
 */
function getRedisClient() {
  if (defaultRedisClient) {
    return defaultRedisClient;
  }

  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    try {
      const client = new Redis(redisUrl, {
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        enableOfflineQueue: false
      });
      client.on('error', () => {
        // Suppress unhandled connection errors when falling back
      });
      defaultRedisClient = client;
      return defaultRedisClient;
    } catch {
      // Fallback to memory
    }
  }

  defaultRedisClient = new MemoryRedis();
  return defaultRedisClient;
}

/**
 * Sets a custom Redis client (e.g. for testing).
 * @param {object|null} client
 */
function setRedisClient(client) {
  defaultRedisClient = client;
}

/**
 * Creates a rate limiting Express middleware backed by Redis.
 * 
 * @param {object} [options]
 * @param {number} [options.limit=60] - Maximum requests allowed in the window
 * @param {number} [options.windowMs=60000] - Window duration in milliseconds (default 1 minute)
 * @param {string} [options.prefix='rl'] - Redis key namespace prefix
 * @param {Function} [options.keyGenerator] - Function generating key from req (default: IP)
 * @param {string} [options.message] - Custom error message for 429
 * @param {object} [options.redisClient] - Explicit Redis client instance
 * @returns {import('express').RequestHandler}
 */
function createRateLimiter(options = {}) {
  const limit = options.limit || 60;
  const windowMs = options.windowMs || 60 * 1000;
  const prefix = options.prefix || 'rl';
  const message = options.message || 'Too many requests. Please try again later.';
  const keyGenerator = options.keyGenerator || ((req) => req.clientIp || req.ip || 'unknown');

  return async function rateLimiterMiddleware(req, res, next) {
    const client = options.redisClient || getRedisClient();
    const identifier = keyGenerator(req);
    const key = `${prefix}:${identifier}`;

    try {
      const count = await client.incr(key);
      if (count === 1) {
        await client.pexpire(key, windowMs);
      }

      let ttlMs = await client.pttl(key);
      if (ttlMs <= 0) {
        ttlMs = windowMs;
        await client.pexpire(key, windowMs);
      }

      const resetTimeSeconds = Math.ceil((Date.now() + ttlMs) / 1000);
      const remaining = Math.max(0, limit - count);

      res.setHeader('X-RateLimit-Limit', limit);
      res.setHeader('X-RateLimit-Remaining', remaining);
      res.setHeader('X-RateLimit-Reset', resetTimeSeconds);

      if (count > limit) {
        const retryAfter = Math.ceil(Math.max(1, ttlMs) / 1000);
        res.setHeader('Retry-After', retryAfter);
        return res.status(429).json({
          error: message,
          retryAfter
        });
      }

      next();
    } catch (err) {
      // In case of Redis failure, fail open to avoid blocking traffic
      next();
    }
  };
}

async function resetRateLimits() {
  const client = getRedisClient();
  if (client && typeof client.flushall === 'function') {
    await client.flushall();
  }
}

// Pre-configured rate limiters
const authLimit = process.env.AUTH_RATE_LIMIT
  ? parseInt(process.env.AUTH_RATE_LIMIT, 10)
  : (process.env.NODE_ENV === 'test' ? 1000 : 15);

const authRateLimiter = createRateLimiter({
  prefix: 'rl:auth',
  limit: authLimit,
  windowMs: 60 * 1000,
  message: 'Too many authentication attempts. Please try again in 1 minute.'
});

const apiRateLimiter = createRateLimiter({
  prefix: 'rl:api',
  limit: 100,
  windowMs: 60 * 1000, // 100 requests / minute
  keyGenerator: (req) => (req.user ? `user:${req.user.id}` : `ip:${req.clientIp || req.ip}`),
  message: 'API rate limit exceeded. Please try again later.'
});

const sensitiveRateLimiter = createRateLimiter({
  prefix: 'rl:sensitive',
  limit: 5,
  windowMs: 60 * 1000, // 5 requests / minute
  message: 'Rate limit exceeded for sensitive operation. Please wait 1 minute.'
});

module.exports = {
  getRedisClient,
  setRedisClient,
  resetRateLimits,
  createRateLimiter,
  authRateLimiter,
  apiRateLimiter,
  sensitiveRateLimiter
};
