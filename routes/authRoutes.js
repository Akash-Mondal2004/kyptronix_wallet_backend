// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const auth = require('../controllers/authController');
const { authenticateToken } = require('../utils/jwt');

// Public routes
router.post('/register', auth.register);
router.post('/verify-registration', auth.verifyRegistration);
router.post('/login', auth.login);
router.post('/verify-otp', auth.verifyOtp);

// Protected routes (require secure authentication)
router.get('/profile', authenticateToken, (req, res) => {
  res.json({ 
    message: 'Protected route accessed successfully',
    user: {
      id: req.user.id,
      mobile: req.user.mobile,
      uid: req.user.uid,
      browser: req.user.browser
    },
    sessionInfo: {
      sessionId: req.user.sessionId,
      deviceBound: true
    }
  });
});

// ✅ NEW: Session management routes
router.post('/logout', authenticateToken, auth.logout);
router.post('/logout-all', authenticateToken, auth.logoutAll);
router.get('/sessions', authenticateToken, auth.getActiveSessions);
router.post('/revoke-session', authenticateToken, auth.revokeSession);

// ✅ NEW: Admin/maintenance routes (should add admin auth in production)
router.post('/cleanup-sessions', auth.cleanupSessions);
router.get('/session-stats', auth.getSessionStats);
router.post('/force-cleanup-all', auth.forceCleanupAllSessions); // Emergency cleanup

module.exports = router;
