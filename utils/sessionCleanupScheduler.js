const SecureJWT = require('./secureJwt');

class SessionCleanupScheduler {
  constructor() {
    this.cleanupInterval = null;
    this.isRunning = false;
  }
  
  /**
   * Start automatic session cleanup
   * @param {number} intervalMinutes - Cleanup interval in minutes (default: 60)
   */
  start(intervalMinutes = 60) {
    if (this.isRunning) {
      console.log('Session cleanup scheduler is already running');
      return;
    }
    
    const intervalMs = intervalMinutes * 60 * 1000;
    
    // Run cleanup immediately
    this.runCleanup();
    
    // Schedule periodic cleanup
    this.cleanupInterval = setInterval(() => {
      this.runCleanup();
    }, intervalMs);
    
    this.isRunning = true;
    console.log(`✅ Session cleanup scheduler started (every ${intervalMinutes} minutes)`);
  }
  
  /**
   * Stop automatic session cleanup
   */
  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.isRunning = false;
    console.log('❌ Session cleanup scheduler stopped');
  }
  
  /**
   * Run cleanup process
   */
  async runCleanup() {
    try {
      console.log('🧹 Starting scheduled session cleanup...');
      
      const stats = await SecureJWT.getSessionStats();
      console.log('Session stats before cleanup:', stats);
      
      // Clean expired sessions
      const expiredCleaned = await SecureJWT.cleanupExpiredSessions();
      
      // Clean old inactive sessions (older than 1 hour)
      const inactiveCleaned = await SecureJWT.forceCleanupInactiveSessions();
      
      const totalCleaned = expiredCleaned + inactiveCleaned;
      
      if (totalCleaned > 0) {
        console.log(`✅ Cleanup completed: ${expiredCleaned} expired, ${inactiveCleaned} inactive sessions deleted`);
      } else {
        console.log('✅ No sessions needed cleanup');
      }
      
      const newStats = await SecureJWT.getSessionStats();
      console.log('Session stats after cleanup:', newStats);
      
    } catch (error) {
      console.error('❌ Scheduled cleanup failed:', error);
    }
  }
  
  /**
   * Get scheduler status
   */
  getStatus() {
    return {
      isRunning: this.isRunning,
      hasInterval: !!this.cleanupInterval
    };
  }
}

// Create singleton instance
const sessionCleanupScheduler = new SessionCleanupScheduler();

module.exports = sessionCleanupScheduler;
