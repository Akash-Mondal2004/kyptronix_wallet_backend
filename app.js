require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { connect } = require("./db/db");
const app = express();
app.use(cors());
app.use(express.json());
const authRoutes = require('./routes/authRoutes');
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 1111;
app.listen(PORT, async () => {
  try {
    await connect;
    console.log("mongoDb connected");
  } catch (error) {
    console.log(error);
  }
  console.log(`server running at port ${PORT}`);
});