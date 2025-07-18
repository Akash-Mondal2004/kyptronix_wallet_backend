require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { connect } = require("./db/db");
const sessionCleanupScheduler = require('./utils/sessionCleanupScheduler');

const app = express();
app.use(cors());
app.use(express.json());
const authRoutes = require('./routes/authRoutes');
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 1111;
app.listen(PORT, async () => {
  try {
    await connect();
    console.log("mongoDb connected");
    
    // ✅ SECURE: Start automatic session cleanup (every 30 minutes)
    sessionCleanupScheduler.start(30);
    
  } catch (error) {
    console.log(error);
  }
  console.log(`server running at port ${PORT}`);
});

// ✅ SECURE: Cleanup on server shutdown
process.on('SIGINT', () => {
  console.log('Server shutting down...');
  sessionCleanupScheduler.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('Server shutting down...');
  sessionCleanupScheduler.stop();
  process.exit(0);
});