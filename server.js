require("dotenv").config();

const app = require("./app");
const connectDB = require("./config/db");

async function start() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI must be configured in .env");
  }

  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET must be configured with at least 32 characters");
  }

  await connectDB();

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
  });
}

start().catch((error) => {
  console.error("Server failed to start:", error);
  process.exit(1);
});
