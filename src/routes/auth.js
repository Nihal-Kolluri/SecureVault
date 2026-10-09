const express = require('express');
const {
  registerUser,
  loginUser,
  refreshSession,
  logoutSession
} = require('../auth/service');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/**
 * Helper to set secure auth cookies.
 */
function setAuthCookies(res, accessToken, refreshToken) {
  const isProduction = process.env.NODE_ENV === 'production';

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 15 * 60 * 1000 // 15 minutes
  });

  if (refreshToken) {
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/api/auth',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
  }
}

/**
 * Clear auth cookies on logout or session termination.
 */
function clearAuthCookies(res) {
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken', { path: '/api/auth' });
}

/**
 * POST /api/auth/register
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await registerUser({ email, password });
    return res.status(201).json({
      message: 'Account created successfully. You can now sign in.',
      user
    });
  } catch (err) {
    return res.status(err.statusCode || 500).json({
      error: err.message || 'Registration failed.'
    });
  }
});

/**
 * POST /api/auth/login
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const ipAddress = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || null;

    const result = await loginUser({
      email,
      password,
      ipAddress,
      userAgent
    });

    setAuthCookies(res, result.accessToken, result.refreshToken);

    return res.status(200).json(result);
  } catch (err) {
    return res.status(err.statusCode || 401).json({
      error: err.message || 'Invalid email or password.'
    });
  }
});

/**
 * POST /api/auth/refresh
 */
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = (req.body && req.body.refreshToken) || (req.cookies && req.cookies.refreshToken);
    const ipAddress = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || null;

    const result = await refreshSession({
      refreshToken,
      ipAddress,
      userAgent
    });

    setAuthCookies(res, result.accessToken, result.refreshToken);

    return res.status(200).json(result);
  } catch (err) {
    clearAuthCookies(res);
    return res.status(err.statusCode || 401).json({
      error: err.message || 'Session expired or invalid.',
      code: err.code || 'UNAUTHORIZED'
    });
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', async (req, res) => {
  try {
    const refreshToken = (req.body && req.body.refreshToken) || (req.cookies && req.cookies.refreshToken);
    await logoutSession(refreshToken);
    clearAuthCookies(res);
    return res.status(200).json({
      message: 'Successfully logged out.'
    });
  } catch (err) {
    clearAuthCookies(res);
    return res.status(200).json({
      message: 'Successfully logged out.'
    });
  }
});

/**
 * GET /api/auth/me
 * Protected endpoint returning active authenticated user identity.
 */
router.get('/me', requireAuth, (req, res) => {
  return res.status(200).json({
    user: req.user
  });
});

module.exports = router;
