// controllers/authController.js
const User = require('../models/user');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sendOtp = require('../utils/sendOtp');
const SecureJWT = require('../utils/secureJwt');

exports.register = async (req, res) => {
  try {
    const { mobile, email, password } = req.body;
    
    // Input validation
    if (!mobile || !email || !password) {
      return res.status(400).json({ message: 'Mobile, email, and password are required' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ mobile }, { email }] });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists with this mobile or email' });
    }
    
    // Generate OTP for verification
    const otp = crypto.randomInt(100000, 999999).toString();
    const uid = 'TabsPay-' + Date.now();
    
    // Create user with unverified status
    const user = new User({ 
      mobile, 
      email, 
      password, 
      uid,
      otp,
      otpExpiry: Date.now() + 5 * 60 * 1000, // 5 minutes
      isVerified: false
    });
    await user.save();
    
    // Send OTP for verification
    await sendOtp(mobile, otp);
    
    res.status(201).json({ 
      message: 'Registration initiated. Please verify your mobile number with the OTP sent.',
      uid: user.uid,
      requiresVerification: true
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.login = async (req, res) => {
  try {
    const { mobile, password } = req.body;
    
    // Input validation
    if (!mobile || !password) {
      return res.status(400).json({ message: 'Mobile and password are required' });
    }
    
    const user = await User.findOne({ mobile });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(403).json({ 
        message: 'Account not verified. Please verify your mobile number first.',
        requiresVerification: true,
        uid: user.uid
      });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    user.otp = otp;
    user.otpExpiry = Date.now() + 5 * 60 * 1000; // 5 mins
    await user.save();

    await sendOtp(user.mobile, otp); // send via SMS or email
    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.verifyOtp = async (req, res) => {
  try {
    const { mobile, otp } = req.body;
    
    // Input validation
    if (!mobile || !otp) {
      return res.status(400).json({ message: 'Mobile and OTP are required' });
    }
    
    const user = await User.findOne({ mobile });

    if (!user || user.otp !== otp || user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    // ✅ SECURE: Generate browser/device-bound token
    const tokenData = await SecureJWT.generateSecureToken(user, req);

    // Clear OTP fields and mark as verified
    user.otp = null;
    user.otpExpiry = null;
    user.isVerified = true;
    await user.save();

    res.json({ 
      token: tokenData.token,
      sessionId: tokenData.sessionId,
      uid: user.uid,
      message: 'Login successful',
      deviceInfo: tokenData.deviceInfo,
      security: {
        browserBound: true,
        sessionManaged: true
      }
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Verify registration OTP
exports.verifyRegistration = async (req, res) => {
  try {
    const { mobile, otp } = req.body;
    
    // Input validation
    if (!mobile || !otp) {
      return res.status(400).json({ message: 'Mobile and OTP are required' });
    }
    
    const user = await User.findOne({ mobile });

    if (!user || user.otp !== otp || user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    // Mark user as verified
    user.otp = null;
    user.otpExpiry = null;
    user.isVerified = true;
    await user.save();

    res.json({ 
      message: 'Registration completed successfully! You can now login.',
      uid: user.uid
    });
  } catch (error) {
    console.error('Registration verification error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// ✅ NEW: Secure logout from current browser/device
exports.logout = async (req, res) => {
  try {
    // Get sessionId from the authenticated user token (set by middleware)
    const userSessionId = req.user?.sessionId;
    
    console.log('Logout attempt:', {
      userSessionId,
      userId: req.user?.id,
      hasSession: !!req.session
    });
    
    if (userSessionId) {
      const revoked = await SecureJWT.revokeSession(userSessionId);
      if (revoked) {
        console.log(`Session ${userSessionId} successfully deleted`);
        res.json({ 
          message: 'Logged out successfully from this browser',
          sessionRevoked: true,
          sessionId: userSessionId
        });
      } else {
        console.log(`Failed to delete session ${userSessionId}`);
        res.status(400).json({ message: 'Session not found or already expired' });
      }
    } else {
      console.log('No sessionId found in user token');
      res.status(400).json({ message: 'No active session found' });
    }
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Logout failed' });
  }
};

// ✅ NEW: Logout from all browsers/devices
exports.logoutAll = async (req, res) => {
  try {
    const userId = req.user.id;
    
    const revokedCount = await SecureJWT.revokeAllUserSessions(userId);
    
    res.json({ 
      message: `Logged out successfully from all devices and browsers`,
      sessionsRevoked: revokedCount
    });
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({ message: 'Logout all failed' });
  }
};

// ✅ NEW: Get all active sessions across browsers/devices
exports.getActiveSessions = async (req, res) => {
  try {
    const userId = req.user.id;
    
    const sessions = await SecureJWT.getUserActiveSessions(userId);
    
    // Add current session indicator
    const currentSessionId = req.user.sessionId;
    const formattedSessions = sessions.map(session => ({
      sessionId: session.sessionId,
      browser: session.deviceInfo.browser,
      browserVersion: session.deviceInfo.browserVersion,
      os: session.deviceInfo.os,
      ip: session.deviceInfo.ip,
      createdAt: session.createdAt,
      lastAccessed: session.lastAccessed,
      isCurrent: session.sessionId === currentSessionId
    }));
    
    res.json({ 
      sessions: formattedSessions,
      totalActiveSessions: formattedSessions.length
    });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ message: 'Failed to get active sessions' });
  }
};

// ✅ NEW: Revoke specific session (logout from specific browser)
exports.revokeSession = async (req, res) => {
  try {
    const { targetSessionId } = req.body;
    const userId = req.user.id;
    
    if (!targetSessionId) {
      return res.status(400).json({ message: 'Session ID is required' });
    }
    
    // Verify the session belongs to the current user
    const sessions = await SecureJWT.getUserActiveSessions(userId);
    const targetSession = sessions.find(s => s.sessionId === targetSessionId);
    
    if (!targetSession) {
      return res.status(404).json({ message: 'Session not found or does not belong to you' });
    }
    
    const revoked = await SecureJWT.revokeSession(targetSessionId);
    
    if (revoked) {
      res.json({ 
        message: `Logged out from ${targetSession.deviceInfo.browser} on ${targetSession.deviceInfo.os}`,
        revokedSession: {
          browser: targetSession.deviceInfo.browser,
          os: targetSession.deviceInfo.os
        }
      });
    } else {
      res.status(400).json({ message: 'Failed to revoke session' });
    }
  } catch (error) {
    console.error('Revoke session error:', error);
    res.status(500).json({ message: 'Failed to revoke session' });
  }
};

// ✅ NEW: Admin endpoint for session cleanup (should be protected with admin auth)
exports.cleanupSessions = async (req, res) => {
  try {
    const stats = await SecureJWT.getSessionStats();
    
    console.log('Session stats before cleanup:', stats);
    
    const expiredCleaned = await SecureJWT.cleanupExpiredSessions();
    const inactiveCleaned = await SecureJWT.forceCleanupInactiveSessions();
    
    const newStats = await SecureJWT.getSessionStats();
    
    res.json({
      message: 'Session cleanup completed',
      before: stats,
      after: newStats,
      cleaned: {
        expired: expiredCleaned,
        inactive: inactiveCleaned,
        total: expiredCleaned + inactiveCleaned
      }
    });
  } catch (error) {
    console.error('Session cleanup error:', error);
    res.status(500).json({ message: 'Session cleanup failed' });
  }
};

// ✅ NEW: Get session statistics
exports.getSessionStats = async (req, res) => {
  try {
    const stats = await SecureJWT.getSessionStats();
    res.json({
      sessionStats: stats,
      recommendations: {
        shouldCleanup: stats.inactive > 10,
        totalDataPoints: stats.total
      }
    });
  } catch (error) {
    console.error('Get session stats error:', error);
    res.status(500).json({ message: 'Failed to get session statistics' });
  }
};

// ✅ NEW: Admin endpoint to force cleanup all sessions (for development)
exports.forceCleanupAllSessions = async (req, res) => {
  try {
    // Only allow in development environment
    if (process.env.NODE_ENV === 'production') {
      return res.status(403).json({ message: 'Not allowed in production' });
    }
    
    const Session = require('../models/session');
    const deleteResult = await Session.deleteMany({});
    
    res.json({ 
      message: `Force cleanup completed`,
      sessionsDeleted: deleteResult.deletedCount,
      warning: 'All users will need to login again'
    });
  } catch (error) {
    console.error('Force cleanup error:', error);
    res.status(500).json({ message: 'Force cleanup failed' });
  }
};
