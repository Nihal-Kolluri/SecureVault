const express = require('express');
const {
  registerUser,
  loginUser,
  verifyMfaLogin,
  refreshSession,
  logoutSession
} = require('../auth/service');
const { requireAuth } = require('../middleware/auth');
const { recordAudit, AUDIT_ACTIONS } = require('../audit/service');

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

    recordAudit({
      action: AUDIT_ACTIONS.AUTH_LOGIN_SUCCESS,
      req,
      actorId: result.user ? result.user.id : null,
      actorEmail: email,
      resourceType: 'session',
      details: { mfaRequired: result.mfaRequired || false }
    });

    return res.status(200).json(result);
  } catch (err) {
    recordAudit({
      action: AUDIT_ACTIONS.AUTH_LOGIN_FAILED,
      req,
      actorEmail: (req.body && req.body.email) || null,
      resourceType: 'auth',
      details: { error: err.message || 'Invalid email or password.' }
    });

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

    recordAudit({
      action: AUDIT_ACTIONS.AUTH_TOKEN_REFRESH,
      req,
      resourceType: 'session'
    });

    return res.status(200).json(result);
  } catch (err) {
    clearAuthCookies(res);

    if (err.code === 'TOKEN_REUSE_DETECTED') {
      recordAudit({
        action: AUDIT_ACTIONS.AUTH_TOKEN_REUSE,
        req,
        resourceType: 'session',
        details: { error: 'Refresh token reuse detected; compromised session revoked' }
      });
    }

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

    recordAudit({
      action: AUDIT_ACTIONS.AUTH_LOGOUT,
      req,
      resourceType: 'session'
    });

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
 * POST /api/auth/mfa/verify
 * Second step in authentication for users with MFA enabled.
 */
router.post('/mfa/verify', async (req, res) => {
  try {
    const { mfaToken, code, recoveryCode } = req.body || {};
    const ipAddress = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || null;

    const result = await verifyMfaLogin({
      mfaToken,
      code,
      recoveryCode,
      ipAddress,
      userAgent
    });

    setAuthCookies(res, result.accessToken, result.refreshToken);

    recordAudit({
      action: recoveryCode ? AUDIT_ACTIONS.MFA_RECOVERY_USED : AUDIT_ACTIONS.AUTH_LOGIN_SUCCESS,
      req,
      actorId: result.user.id,
      actorEmail: result.user.email,
      resourceType: 'mfa',
      details: { method: recoveryCode ? 'recovery_code' : 'totp' }
    });

    return res.status(200).json(result);
  } catch (err) {
    recordAudit({
      action: AUDIT_ACTIONS.MFA_FAILED,
      req,
      resourceType: 'mfa',
      details: { error: err.message }
    });

    return res.status(err.statusCode || 401).json({
      error: err.message || 'Invalid authentication code.'
    });
  }
});

/**
 * POST /api/auth/mfa/setup
 * Generates TOTP secret, QR code, and emergency recovery codes for authenticated user.
 */
router.post('/mfa/setup', requireAuth, async (req, res) => {
  try {
    const { generateTotpEnrollment, generateRecoveryCodes, generateMfaSetupToken } = require('../auth/mfa');
    const { secret, otpAuthUrl, qrCodeDataUrl } = await generateTotpEnrollment(req.user.email);
    const recoveryCodes = generateRecoveryCodes(8);
    const setupToken = generateMfaSetupToken(req.user.id, secret, recoveryCodes);

    recordAudit({
      action: AUDIT_ACTIONS.MFA_SETUP_INIT,
      req,
      resourceType: 'mfa',
      resourceId: req.user.id
    });

    return res.status(200).json({
      secret,
      otpAuthUrl,
      qrCode: qrCodeDataUrl,
      recoveryCodes,
      setupToken
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to initiate MFA setup.'
    });
  }
});

/**
 * POST /api/auth/mfa/confirm
 * Validates initial code and enables MFA on the user account.
 */
router.post('/mfa/confirm', requireAuth, async (req, res) => {
  try {
    const { confirmMfaEnrollment } = require('../auth/mfa');
    const { setupToken, code } = req.body || {};

    await confirmMfaEnrollment(req.user.id, setupToken, code);

    recordAudit({
      action: AUDIT_ACTIONS.MFA_ENABLE,
      req,
      resourceType: 'mfa',
      resourceId: req.user.id
    });

    return res.status(200).json({
      message: 'Two-factor authentication successfully enabled.'
    });
  } catch (err) {
    return res.status(err.statusCode || 400).json({
      error: err.message || 'Failed to confirm MFA setup.'
    });
  }
});

/**
 * POST /api/auth/mfa/disable
 * Disables MFA for the user account.
 */
router.post('/mfa/disable', requireAuth, (req, res) => {
  try {
    const { disableMfa } = require('../auth/mfa');
    disableMfa(req.user.id);

    recordAudit({
      action: AUDIT_ACTIONS.MFA_DISABLE,
      req,
      resourceType: 'mfa',
      resourceId: req.user.id
    });

    return res.status(200).json({
      message: 'Two-factor authentication has been disabled.'
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to disable MFA.'
    });
  }
});

/**
 * GET /api/auth/mfa/status
 * Returns current MFA status and remaining recovery code count.
 */
router.get('/mfa/status', requireAuth, (req, res) => {
  try {
    const { getRemainingRecoveryCodesCount } = require('../auth/mfa');
    const { getUserById } = require('../auth/service');
    const user = getUserById(req.user.id);

    return res.status(200).json({
      mfaEnabled: user ? user.mfaEnabled : false,
      remainingRecoveryCodes: user && user.mfaEnabled ? getRemainingRecoveryCodesCount(req.user.id) : 0
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to retrieve MFA status.'
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
