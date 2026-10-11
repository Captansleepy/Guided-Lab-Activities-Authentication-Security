const express = require("express");
const authRoutes = require("./routes/auth");
const studentRoutes = require("./routes/students");
const errorHandler = require("./middleware/errorHandler");

const app = express();

app.use(express.json());
app.use("/api/auth", authRoutes);
app.use("/api/students", studentRoutes);

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use(errorHandler);

module.exports = app;
