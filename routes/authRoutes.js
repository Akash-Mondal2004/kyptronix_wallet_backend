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

// Protected routes (require authentication)
router.get('/profile', authenticateToken, (req, res) => {
  res.json({ 
    message: 'Protected route accessed successfully',
    user: req.user 
  });
});

module.exports = router;
