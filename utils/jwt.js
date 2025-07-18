const SecureJWT = require('./secureJwt');

// Generate JWT token (keeping for compatibility)
const generateToken = (payload) => {
  console.warn('Warning: Using basic generateToken. Consider using SecureJWT for better security.');
  const jwt = require('jsonwebtoken');
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
};

// Verify JWT token (keeping for compatibility)
const verifyToken = (token) => {
  try {
    const jwt = require('jsonwebtoken');
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    throw new Error('Invalid token');
  }
};

// ✅ SECURE: Enhanced middleware with browser/device binding
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ 
        message: 'Access token required',
        code: 'NO_TOKEN'
      });
    }

    // ✅ SECURE: Verify token with device/browser binding
    const verificationResult = await SecureJWT.verifySecureToken(token, req);
    
    req.user = verificationResult.user;
    req.session = verificationResult.session;
    next();
    
  } catch (error) {
    console.error('Authentication error:', error.message);
    
    // Handle different types of security errors
    if (error.message.includes('SECURITY_ALERT')) {
      return res.status(403).json({ 
        message: 'Security Alert: This token cannot be used from this browser. Please login again.',
        code: 'DEVICE_MISMATCH',
        action: 'FORCE_LOGOUT'
      });
    }
    
    if (error.message.includes('Session expired')) {
      return res.status(401).json({ 
        message: 'Your session has expired. Please login again.',
        code: 'SESSION_EXPIRED',
        action: 'REDIRECT_LOGIN'
      });
    }
    
    if (error.message.includes('Token has expired')) {
      return res.status(401).json({ 
        message: 'Your login session has expired. Please login again.',
        code: 'TOKEN_EXPIRED',
        action: 'REDIRECT_LOGIN'
      });
    }
    
    if (error.message.includes('Invalid token')) {
      return res.status(403).json({ 
        message: 'Invalid authentication token.',
        code: 'INVALID_TOKEN',
        action: 'REDIRECT_LOGIN'
      });
    }
    
    // Default error
    return res.status(403).json({ 
      message: 'Authentication failed. Please login again.',
      code: 'AUTH_FAILED',
      action: 'REDIRECT_LOGIN'
    });
  }
};

module.exports = {
  generateToken,
  verifyToken,
  authenticateToken
};
