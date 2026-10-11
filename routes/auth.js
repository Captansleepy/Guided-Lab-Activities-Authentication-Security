const bcrypt = require("bcrypt");
const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const auth = require("../middleware/auth");

const router = express.Router();

router.post("/register", async (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    return res.status(400).json({ error: "A valid email is required" });
  }

  if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
    return res.status(400).json({
      error: "Password must be at least 8 characters and no more than 72 bytes"
    });
  }

  const user = await User.create({ email: normalizedEmail, password });
  return res.status(201).json({
    id: user._id,
    email: user.email,
    role: user.role
  });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }

  if (Buffer.byteLength(password, "utf8") > 72) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const user = await User.findOne({ email: email.trim().toLowerCase() }).select("+password");
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user._id.toString(), role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  return res.json({ token });
});

router.get("/me", auth, (req, res) => {
  return res.json({ id: req.user.id, role: req.user.role });
});

module.exports = router;
