const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  sessionId: { 
    type: String, 
    required: true, 
    unique: true 
  },
  deviceFingerprint: { 
    type: String, 
    required: true 
  },
  deviceInfo: {
    browser: String,
    browserVersion: String,
    os: String,
    userAgent: { type: String, select: false }, // Hide sensitive data by default
    ip: { type: String, select: false } // Hide IP by default
  },
  isActive: { 
    type: Boolean, 
    default: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  lastAccessed: { 
    type: Date, 
    default: Date.now 
  },
  expiresAt: { 
    type: Date, 
    required: true 
  }
});

// Index for automatic cleanup of expired sessions
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Index for faster queries
sessionSchema.index({ userId: 1, isActive: 1 });
sessionSchema.index({ sessionId: 1, isActive: 1 });

// ✅ NEW: Index for cleanup of old inactive sessions
sessionSchema.index({ isActive: 1, lastAccessed: 1 });

// Update lastAccessed on every access
sessionSchema.methods.updateLastAccessed = function() {
  this.lastAccessed = new Date();
  return this.save();
};

// Check if session is expired
sessionSchema.methods.isExpired = function() {
  return this.expiresAt < new Date();
};

// ✅ NEW: Anonymize sensitive data before deletion (for audit trail)
sessionSchema.methods.anonymize = function() {
  this.deviceFingerprint = 'ANONYMIZED';
  this.deviceInfo.userAgent = 'ANONYMIZED';
  this.deviceInfo.ip = 'ANONYMIZED';
  this.isActive = false;
  return this.save();
};

// ✅ NEW: Pre-remove hook for logging (optional)
sessionSchema.pre('deleteOne', { document: true, query: false }, function() {
  console.log(`Session ${this.sessionId} being deleted for user ${this.userId}`);
});

sessionSchema.pre('deleteMany', function() {
  console.log('Bulk session deletion in progress...');
});

module.exports = mongoose.model('Session', sessionSchema);
