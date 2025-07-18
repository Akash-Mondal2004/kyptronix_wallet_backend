const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Session = require('../models/session');
const DeviceFingerprint = require('./deviceFingerprint');

class SecureJWT {
  /**
   * Generate a secure token bound to specific browser/device
   */
  static async generateSecureToken(user, req) {
    try {
      // Generate device fingerprint for this specific browser
      const deviceFingerprint = DeviceFingerprint.generateFingerprint(req);
      
      // Generate unique session ID
      const sessionId = crypto.randomUUID();
      
      // Extract device and browser information
      const browserInfo = DeviceFingerprint.extractBrowserInfo(req.headers['user-agent']);
      const osInfo = DeviceFingerprint.extractOSInfo(req.headers['user-agent']);
      
      const deviceInfo = {
        browser: browserInfo.browser,
        browserVersion: browserInfo.version,
        os: osInfo,
        userAgent: req.headers['user-agent'] || '',
        ip: req.ip || req.connection.remoteAddress || ''
      };
      
      // Create session record in database
      const session = new Session({
        userId: user._id,
        sessionId,
        deviceFingerprint,
        deviceInfo,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      });
      
      await session.save();
      
      // Create JWT payload with session binding
      const payload = {
        id: user._id,
        mobile: user.mobile,
        uid: user.uid,
        sessionId,
        deviceFingerprint,
        browser: browserInfo.browser,
        type: 'access_token',
        iat: Math.floor(Date.now() / 1000)
      };
      
      // Generate JWT token
      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: '7d',
        issuer: 'TabsPay-Wallet',
        audience: 'TabsPay-Users',
        algorithm: 'HS256'
      });
      
      return { 
        token, 
        sessionId,
        deviceInfo: {
          browser: browserInfo.browser,
          browserVersion: browserInfo.version,
          os: osInfo
        }
      };
      
    } catch (error) {
      console.error('Secure token generation failed:', error);
      throw new Error(`Token generation failed: ${error.message}`);
    }
  }
  
  /**
   * Verify token and ensure it's being used from the same browser
   */
  static async verifySecureToken(token, req) {
    try {
      // Verify JWT signature and structure
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        issuer: 'TabsPay-Wallet',
        audience: 'TabsPay-Users',
        algorithms: ['HS256']
      });
      
      // Generate current device fingerprint
      const currentFingerprint = DeviceFingerprint.generateFingerprint(req);
      
      // CRITICAL: Check if device fingerprint matches
      if (decoded.deviceFingerprint !== currentFingerprint) {
        console.error('Security Alert: Device fingerprint mismatch', {
          stored: decoded.deviceFingerprint,
          current: currentFingerprint,
          userAgent: req.headers['user-agent'],
          ip: req.ip,
          sessionId: decoded.sessionId
        });
        throw new Error('SECURITY_ALERT: Token used from different browser/device');
      }
      
      // Verify session exists and is active
      const session = await Session.findOne({
        sessionId: decoded.sessionId,
        userId: decoded.id,
        isActive: true,
        expiresAt: { $gt: new Date() }
      });
      
      if (!session) {
        throw new Error('Session expired or revoked');
      }
      
      // Update last accessed time
      await session.updateLastAccessed();
      
      return {
        user: decoded,
        session: session
      };
      
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token signature');
      }
      if (error.name === 'TokenExpiredError') {
        throw new Error('Token has expired');
      }
      throw error;
    }
  }
  
  /**
   * Revoke a specific session (with immediate cleanup)
   */
  static async revokeSession(sessionId) {
    try {
      // ✅ SECURE: Delete session immediately instead of just marking inactive
      const result = await Session.findOneAndDelete({
        sessionId,
        isActive: true
      });
      
      if (result) {
        console.log(`Session ${sessionId} deleted immediately for security`);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Session revocation failed:', error);
      return false;
    }
  }
  
  /**
   * Revoke all sessions for a user (with immediate cleanup)
   */
  static async revokeAllUserSessions(userId) {
    try {
      // ✅ SECURE: Delete all user sessions immediately
      const result = await Session.deleteMany({
        userId,
        isActive: true
      });
      
      console.log(`Deleted ${result.deletedCount} sessions for user ${userId}`);
      return result.deletedCount;
    } catch (error) {
      console.error('Bulk session revocation failed:', error);
      return 0;
    }
  }
  
  /**
   * Get all active sessions for a user
   */
  static async getUserActiveSessions(userId) {
    try {
      return await Session.find({
        userId,
        isActive: true,
        expiresAt: { $gt: new Date() }
      }).select('sessionId deviceInfo createdAt lastAccessed').sort({ lastAccessed: -1 });
    } catch (error) {
      console.error('Get user sessions failed:', error);
      return [];
    }
  }
  
  /**
   * Clean up expired sessions and old inactive sessions
   */
  static async cleanupExpiredSessions() {
    try {
      // Delete expired sessions
      const expiredResult = await Session.deleteMany({
        expiresAt: { $lt: new Date() }
      });
      
      // ✅ SECURE: Also delete old inactive sessions (older than 1 hour)
      const oldInactiveResult = await Session.deleteMany({
        isActive: false,
        lastAccessed: { $lt: new Date(Date.now() - 60 * 60 * 1000) } // 1 hour ago
      });
      
      const totalCleaned = expiredResult.deletedCount + oldInactiveResult.deletedCount;
      
      if (totalCleaned > 0) {
        console.log(`Cleaned up ${expiredResult.deletedCount} expired and ${oldInactiveResult.deletedCount} old inactive sessions`);
      }
      
      return totalCleaned;
    } catch (error) {
      console.error('Session cleanup failed:', error);
      return 0;
    }
  }
  
  /**
   * ✅ NEW: Force cleanup of all inactive sessions
   */
  static async forceCleanupInactiveSessions() {
    try {
      const result = await Session.deleteMany({
        isActive: false
      });
      
      console.log(`Force cleaned ${result.deletedCount} inactive sessions`);
      return result.deletedCount;
    } catch (error) {
      console.error('Force cleanup failed:', error);
      return 0;
    }
  }
  
  /**
   * ✅ NEW: Get session statistics
   */
  static async getSessionStats() {
    try {
      const totalSessions = await Session.countDocuments();
      const activeSessions = await Session.countDocuments({ isActive: true });
      const expiredSessions = await Session.countDocuments({ 
        expiresAt: { $lt: new Date() } 
      });
      
      return {
        total: totalSessions,
        active: activeSessions,
        inactive: totalSessions - activeSessions,
        expired: expiredSessions
      };
    } catch (error) {
      console.error('Get session stats failed:', error);
      return { total: 0, active: 0, inactive: 0, expired: 0 };
    }
  }
}

module.exports = SecureJWT;
