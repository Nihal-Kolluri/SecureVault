const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const express = require('express');
const { getClientIp, normalizeIp, isTrustedProxy } = require('../src/gateway/ip');
const { createGatewayMiddleware } = require('../src/gateway/gateway');
const {
  createRateLimiter,
  getRedisClient,
  resetRateLimits
} = require('../src/gateway/rate-limiter');
const { createApp } = require('../src/app');
const { initDatabase, closeDatabase } = require('../src/db/database');

test.beforeEach(async () => {
  await resetRateLimits();
});

/* -------------------------------------------------------------------------- */
/*                       1. Anti-Spoofing IP Extraction                       */
/* -------------------------------------------------------------------------- */

test('IP extraction: normalizes IPv6-mapped IPv4 addresses', () => {
  assert.equal(normalizeIp('::ffff:192.168.1.1'), '192.168.1.1');
  assert.equal(normalizeIp('  ::ffff:10.0.0.5  '), '10.0.0.5');
  assert.equal(normalizeIp('127.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIp(''), '127.0.0.1');
});

test('IP extraction: strictly ignores spoofed X-Forwarded-For when trustProxy is false', () => {
  const req = {
    socket: { remoteAddress: '203.0.113.195' },
    headers: {
      'x-forwarded-for': '198.51.100.22, 198.51.100.23'
    }
  };

  const clientIp = getClientIp(req, { trustProxy: false });
  assert.equal(clientIp, '203.0.113.195', 'Must ignore X-Forwarded-For when trustProxy is false');
});

test('IP extraction: accepts X-Forwarded-For client IP when trustProxy is true', () => {
  const req = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: {
      'x-forwarded-for': '198.51.100.44, 10.0.0.1'
    }
  };

  const clientIp = getClientIp(req, { trustProxy: true });
  assert.equal(clientIp, '198.51.100.44', 'Must extract client IP when trustProxy is true');
});

test('IP extraction: validates against trusted proxy whitelist', () => {
  const trustedProxies = ['10.0.0.1', '10.0.0.2'];

  // Case 1: Untrusted immediate socket sends spoofed header -> ignored
  const untrustedReq = {
    socket: { remoteAddress: '203.0.113.50' },
    headers: {
      'x-forwarded-for': '1.2.3.4'
    }
  };
  assert.equal(
    getClientIp(untrustedReq, { trustProxy: trustedProxies }),
    '203.0.113.50',
    'Must ignore X-Forwarded-For if socket IP is not in trusted proxy whitelist'
  );

  // Case 2: Trusted proxy sends header chain -> resolves client IP
  const trustedReq = {
    socket: { remoteAddress: '10.0.0.1' },
    headers: {
      'x-forwarded-for': '198.51.100.99, 10.0.0.2'
    }
  };
  assert.equal(
    getClientIp(trustedReq, { trustProxy: trustedProxies }),
    '198.51.100.99',
    'Must resolve true client IP through trusted proxy chain'
  );
});

/* -------------------------------------------------------------------------- */
/*                        2. Gateway Middleware Stack                         */
/* -------------------------------------------------------------------------- */

test('Gateway middleware: sets security headers and generates X-Request-Id', async () => {
  const app = createApp({ trustProxy: false });

  const res = await request(app).get('/api/status');

  assert.equal(res.status, 200);
  assert.ok(res.headers['x-request-id'], 'Must generate X-Request-Id');
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['x-frame-options'], 'DENY');
  assert.equal(res.headers['x-xss-protection'], '0');
  assert.match(res.headers['strict-transport-security'], /max-age=31536000/);
  assert.match(res.headers['content-security-policy'], /default-src 'self'/);
});

test('Gateway middleware: preserves existing valid X-Request-Id', async () => {
  const app = createApp({ trustProxy: false });
  const customRequestId = 'req-trace-abc-12345';

  const res = await request(app)
    .get('/api/status')
    .set('X-Request-Id', customRequestId);

  assert.equal(res.status, 200);
  assert.equal(res.headers['x-request-id'], customRequestId);
});

/* -------------------------------------------------------------------------- */
/*                       3. Redis Rate Limiter & Headers                      */
/* -------------------------------------------------------------------------- */

test('Rate limiter: emits X-RateLimit headers and enforces limits', async () => {
  const limiterApp = express();
  const testLimiter = createRateLimiter({
    prefix: 'rl:test_limit',
    limit: 3,
    windowMs: 60 * 1000,
    keyGenerator: (req) => req.clientIp || 'test-client'
  });

  limiterApp.use((req, res, next) => {
    req.clientIp = '192.0.2.1';
    next();
  });
  limiterApp.use(testLimiter);
  limiterApp.get('/test', (req, res) => res.json({ ok: true }));

  // Request 1: remaining 2
  const res1 = await request(limiterApp).get('/test');
  assert.equal(res1.status, 200);
  assert.equal(res1.headers['x-ratelimit-limit'], '3');
  assert.equal(res1.headers['x-ratelimit-remaining'], '2');
  assert.ok(res1.headers['x-ratelimit-reset']);

  // Request 2: remaining 1
  const res2 = await request(limiterApp).get('/test');
  assert.equal(res2.status, 200);
  assert.equal(res2.headers['x-ratelimit-remaining'], '1');

  // Request 3: remaining 0
  const res3 = await request(limiterApp).get('/test');
  assert.equal(res3.status, 200);
  assert.equal(res3.headers['x-ratelimit-remaining'], '0');

  // Request 4: limit exceeded -> 429
  const res4 = await request(limiterApp).get('/test');
  assert.equal(res4.status, 429);
  assert.ok(res4.headers['retry-after']);
  assert.match(res4.body.error, /Too many requests/);
});

/* -------------------------------------------------------------------------- */
/*                 4. Spoofed X-Forwarded-For Defense Under Test              */
/* -------------------------------------------------------------------------- */

test('Rate limiter: blocks attacker attempting to bypass rate limits with spoofed X-Forwarded-For', async () => {
  // App configured with trustProxy: false (default direct connection)
  const app = express();
  app.use(createGatewayMiddleware({ trustProxy: false }));

  const rateLimiter = createRateLimiter({
    prefix: 'rl:spoof_test',
    limit: 2,
    windowMs: 60 * 1000,
    keyGenerator: (req) => req.clientIp
  });

  app.use(rateLimiter);
  app.get('/test-anti-spoof', (req, res) => res.json({ ip: req.clientIp }));

  // Attacker sends Request 1 with spoofed header "1.1.1.1"
  const res1 = await request(app)
    .get('/test-anti-spoof')
    .set('X-Forwarded-For', '1.1.1.1');
  assert.equal(res1.status, 200);

  // Attacker sends Request 2 with spoofed header "2.2.2.2"
  const res2 = await request(app)
    .get('/test-anti-spoof')
    .set('X-Forwarded-For', '2.2.2.2');
  assert.equal(res2.status, 200);

  // Attacker sends Request 3 with spoofed header "3.3.3.3" -> MUST BE BLOCKED (429)!
  const res3 = await request(app)
    .get('/test-anti-spoof')
    .set('X-Forwarded-For', '3.3.3.3');

  assert.equal(
    res3.status,
    429,
    'Attacker must not bypass rate limit by varying X-Forwarded-For when trustProxy is false'
  );
  assert.ok(res3.headers['retry-after'], 'Must contain Retry-After header on 429');
});
