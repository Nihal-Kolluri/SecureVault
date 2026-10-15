const { verifyAccessToken } = require('../auth/tokens');
const { getUserById } = require('../auth/service');

/**
 * Express middleware that validates the 15-minute access JWT.
 */
function requireAuth(req, res, next) {
  let token = null;

  // Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.cookies && req.cookies.accessToken) {
    // Check httpOnly cookie
    token = req.cookies.accessToken;
  }

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required. Please sign in.'
    });
  }

  try {
    const payload = verifyAccessToken(token);
    const user = getUserById(payload.sub);
    if (!user) {
      return res.status(401).json({
        error: 'User account not found.'
      });
    }

    req.user = {
      id: user.id,
      email: user.email,
      role: user.role || 'user',
      sessionId: payload.sid || null
    };

    if (req.user.sessionId) {
      const { getDatabase } = require('../db/database');
      const db = getDatabase();
      const sess = db.prepare('SELECT is_revoked FROM sessions WHERE id = ?').get(req.user.sessionId);
      if (sess && sess.is_revoked === 1) {
        return res.status(401).json({
          error: 'Session has been revoked. Please sign in again.',
          code: 'SESSION_REVOKED'
        });
      }
    }

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access token expired. Please refresh session.',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(401).json({
      error: 'Invalid authentication token.'
    });
  }
}

module.exports = {
  requireAuth
};
