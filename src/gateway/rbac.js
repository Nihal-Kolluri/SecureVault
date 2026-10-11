/**
 * Role-Based Access Control (RBAC) Middleware
 * Enforces role authorization across administrative and privileged endpoints.
 */

const ROLES = {
  ADMIN: 'admin',
  MANAGER: 'manager',
  USER: 'user'
};

/**
 * Checks if a user has any of the specified roles.
 * @param {object} user
 * @param {string[]} allowedRoles
 * @returns {boolean}
 */
function hasRole(user, ...allowedRoles) {
  if (!user || !user.role) return false;
  return allowedRoles.includes(user.role);
}

/**
 * Express middleware requiring one of the specified roles.
 * @param {...string} allowedRoles
 * @returns {import('express').RequestHandler}
 */
function requireRole(...allowedRoles) {
  return function rbacMiddleware(req, res, next) {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required.'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden: Insufficient privileges.'
      });
    }

    next();
  };
}

module.exports = {
  ROLES,
  hasRole,
  requireRole
};
