const mongoose = require("mongoose");

const connect = async () => {
  try {
    await mongoose.connect(
      process.env.MONGODB_URI ,
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log("✅ MongoDB connected successfully");
  } catch (error) {
    console.error("❌ MongoDB connection error:", error.message);
    process.exit(1); // Optional: Exit process if DB fails to connect
  }
};

module.exports = { connect };
