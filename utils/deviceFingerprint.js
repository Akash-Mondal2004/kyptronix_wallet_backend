const crypto = require('crypto');

class DeviceFingerprint {
  /**
   * Generate a unique fingerprint for browser/device combination
   * Simplified approach for better reliability
   */
  static generateFingerprint(req) {
    try {
      // Use only User-Agent as the primary identifier
      // This is stable across requests from the same browser
      const userAgent = req.headers['user-agent'] || 'unknown-browser';
      
      // Generate a consistent hash based only on User-Agent
      // This provides browser-level security without IP complications
      return crypto.createHash('sha256').update(userAgent).digest('hex');
    } catch (error) {
      console.error('Fingerprint generation error:', error);
      return crypto.randomBytes(32).toString('hex');
    }
  }
  
  /**
   * Verify if current request matches stored fingerprint
   */
  static verifyFingerprint(storedFingerprint, currentFingerprint) {
    return storedFingerprint === currentFingerprint;
  }
  
  /**
   * Extract browser information
   */
  static extractBrowserInfo(userAgent) {
    if (!userAgent) return { browser: 'Unknown', version: 'Unknown' };
    
    // Chrome detection
    if (userAgent.includes('Chrome') && !userAgent.includes('Edge')) {
      const version = userAgent.match(/Chrome\/([0-9.]+)/)?.[1] || 'Unknown';
      return { browser: 'Chrome', version };
    }
    
    // Firefox detection
    if (userAgent.includes('Firefox')) {
      const version = userAgent.match(/Firefox\/([0-9.]+)/)?.[1] || 'Unknown';
      return { browser: 'Firefox', version };
    }
    
    // Edge detection
    if (userAgent.includes('Edge') || userAgent.includes('Edg/')) {
      const version = userAgent.match(/Edg?\/([0-9.]+)/)?.[1] || 'Unknown';
      return { browser: 'Edge', version };
    }
    
    // Safari detection
    if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
      const version = userAgent.match(/Version\/([0-9.]+)/)?.[1] || 'Unknown';
      return { browser: 'Safari', version };
    }
    
    return { browser: 'Other', version: 'Unknown' };
  }
  
  /**
   * Extract OS information
   */
  static extractOSInfo(userAgent) {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Windows NT 10.0')) return 'Windows 10/11';
    if (userAgent.includes('Windows NT 6.3')) return 'Windows 8.1';
    if (userAgent.includes('Windows NT 6.1')) return 'Windows 7';
    if (userAgent.includes('Windows')) return 'Windows';
    
    if (userAgent.includes('Mac OS X')) {
      const version = userAgent.match(/Mac OS X ([0-9_]+)/)?.[1]?.replace(/_/g, '.') || '';
      return `macOS ${version}`;
    }
    
    if (userAgent.includes('Linux')) return 'Linux';
    if (userAgent.includes('Android')) return 'Android';
    if (userAgent.includes('iPhone') || userAgent.includes('iPad')) return 'iOS';
    
    return 'Unknown';
  }
}

module.exports = DeviceFingerprint;
