const assert = require("node:assert/strict");
const test = require("node:test");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const requireRole = require("../middleware/requireRole");
const errorHandler = require("../middleware/errorHandler");

process.env.JWT_SECRET = "a-test-secret-that-is-long-enough-for-signing";

function responseRecorder() {
  return {
    statusCode: 200,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    }
  };
}

test("auth rejects a missing bearer token", () => {
  const res = responseRecorder();
  auth({ headers: {} }, res, () => assert.fail("next should not be called"));

  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: "No token provided" });
});

test("auth rejects an invalid bearer token", () => {
  const res = responseRecorder();
  auth(
    { headers: { authorization: "Bearer invalid" } },
    res,
    () => assert.fail("next should not be called")
  );

  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: "Invalid token" });
});

test("auth attaches verified identity from a valid token", () => {
  const token = jwt.sign({ id: "user-1", role: "user" }, process.env.JWT_SECRET);
  const req = { headers: { authorization: `Bearer ${token}` } };
  const res = responseRecorder();
  let nextCalled = false;

  auth(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.deepEqual(req.user, { id: "user-1", role: "user" });
});

test("auth accepts a case-insensitive bearer scheme", () => {
  const token = jwt.sign({ id: "user-1", role: "user" }, process.env.JWT_SECRET);
  const req = { headers: { authorization: `bearer ${token}` } };
  const res = responseRecorder();
  let nextCalled = false;

  auth(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.deepEqual(req.user, { id: "user-1", role: "user" });
});

test("auth rejects extra components after a valid token", () => {
  const token = jwt.sign({ id: "user-1", role: "user" }, process.env.JWT_SECRET);
  const req = { headers: { authorization: `Bearer ${token} extra` } };
  const res = responseRecorder();

  auth(req, res, () => assert.fail("next should not be called"));

  assert.equal(res.statusCode, 401);
  assert.equal(req.user, undefined);
});

test("auth rejects an expired token", () => {
  const token = jwt.sign({ id: "user-1", role: "user" }, process.env.JWT_SECRET, {
    expiresIn: -1
  });
  const req = { headers: { authorization: `Bearer ${token}` } };
  const res = responseRecorder();

  auth(req, res, () => assert.fail("next should not be called"));

  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: "Invalid token" });
  assert.equal(req.user, undefined);
});

test("auth rejects a token whose role was altered without resigning", () => {
  const token = jwt.sign({ id: "user-1", role: "user" }, process.env.JWT_SECRET);
  const parts = token.split(".");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  payload.role = "admin";
  parts[1] = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const req = { headers: { authorization: `Bearer ${parts.join(".")}` } };
  const res = responseRecorder();

  auth(req, res, () => assert.fail("next should not be called"));

  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: "Invalid token" });
  assert.equal(req.user, undefined);
});

test("auth rejects signed tokens missing required identity claims", () => {
  for (const payload of [{ id: "user-1" }, { role: "user" }]) {
    const token = jwt.sign(payload, process.env.JWT_SECRET);
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = responseRecorder();

    auth(req, res, () => assert.fail("next should not be called"));

    assert.equal(res.statusCode, 401);
    assert.deepEqual(res.body, { error: "Invalid token" });
    assert.equal(req.user, undefined);
  }
});

test("requireRole returns forbidden for users without the required role", () => {
  const res = responseRecorder();
  requireRole("admin")({ user: { role: "user" } }, res, () => {
    assert.fail("next should not be called");
  });

  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { error: "Forbidden" });
});

test("requireRole allows an authenticated admin", () => {
  const res = responseRecorder();
  let nextCalled = false;

  requireRole("admin")({ user: { id: "admin-1", role: "admin" } }, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body, undefined);
});

test("requireRole rejects a request without an authenticated identity", () => {
  const res = responseRecorder();

  requireRole("admin")({}, res, () => assert.fail("next should not be called"));

  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { error: "Forbidden" });
});

test("oversized JSON receives 413 through the actual body parser", async (t) => {
  const express = require("express");
  const app = express();
  app.use(express.json());
  app.post("/", () => assert.fail("oversized body should not reach the route"));
  app.use(errorHandler);

  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const response = await fetch(`http://127.0.0.1:${server.address().port}/`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Connection: "close" },
    body: JSON.stringify({ value: "x".repeat(110000) })
  });

  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { error: "Request body too large" });
});
