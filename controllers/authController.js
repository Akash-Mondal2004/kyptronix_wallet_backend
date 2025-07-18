// controllers/authController.js
const User = require('../models/user');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sendOtp = require('../utils/sendOtp');
const { generateToken } = require('../utils/jwt');

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

    // Generate JWT token using the utility
    const token = generateToken({ 
      id: user._id, 
      mobile: user.mobile,
      uid: user.uid 
    });

    // Clear OTP fields and mark as verified
    user.otp = null;
    user.otpExpiry = null;
    user.isVerified = true;
    await user.save();

    res.json({ 
      token, 
      uid: user.uid,
      message: 'Login successful' 
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
