const express = require("express");
const mongoose = require("mongoose");
const Student = require("../models/Student");
const auth = require("../middleware/auth");
const requireRole = require("../middleware/requireRole");

const router = express.Router();
const allowedFields = ["name", "major", "score"];

function validStudentFields(body, { partial = false } = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return false;
  }

  const keys = Object.keys(body);
  if (keys.length === 0 || keys.some((key) => !allowedFields.includes(key))) {
    return false;
  }

  if (!partial && allowedFields.some((key) => !(key in body))) {
    return false;
  }

  return keys.every((key) => {
    if (key === "score") {
      return typeof body.score === "number" && Number.isFinite(body.score);
    }
    return typeof body[key] === "string" && body[key].trim().length > 0;
  });
}

function validId(id) {
  return mongoose.isValidObjectId(id);
}

router.get("/", async (req, res) => {
  const students = await Student.find().sort({ createdAt: -1 });
  return res.json(students);
});

router.get("/:id", async (req, res) => {
  if (!validId(req.params.id)) {
    return res.status(400).json({ error: "Invalid student ID" });
  }

  const student = await Student.findById(req.params.id);
  if (!student) {
    return res.status(404).json({ error: "Student not found" });
  }

  return res.json(student);
});

router.post("/", auth, async (req, res) => {
  if (!validStudentFields(req.body)) {
    return res.status(400).json({ error: "Name, major, and numeric score are required" });
  }

  const student = await Student.create({
    name: req.body.name.trim(),
    major: req.body.major.trim(),
    score: req.body.score
  });
  return res.status(201).json(student);
});

router.patch("/:id", auth, async (req, res) => {
  if (!validId(req.params.id)) {
    return res.status(400).json({ error: "Invalid student ID" });
  }

  if (!validStudentFields(req.body, { partial: true })) {
    return res.status(400).json({ error: "Provide valid student fields to update" });
  }

  const changes = { ...req.body };
  for (const key of ["name", "major"]) {
    if (key in changes) {
      changes[key] = changes[key].trim();
    }
  }

  const student = await Student.findByIdAndUpdate(req.params.id, changes, {
    new: true,
    runValidators: true
  });
  if (!student) {
    return res.status(404).json({ error: "Student not found" });
  }

  return res.json(student);
});

router.delete("/:id", auth, requireRole("admin"), async (req, res) => {
  if (!validId(req.params.id)) {
    return res.status(400).json({ error: "Invalid student ID" });
  }

  const student = await Student.findByIdAndDelete(req.params.id);
  if (!student) {
    return res.status(404).json({ error: "Student not found" });
  }

  return res.status(204).end();
});

module.exports = router;
