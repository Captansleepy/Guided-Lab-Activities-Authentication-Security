const assert = require("node:assert/strict");
const test = require("node:test");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const requireRole = require("../middleware/requireRole");

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
  process.env.JWT_SECRET = "a-test-secret-that-is-long-enough-for-signing";
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

test("requireRole returns forbidden for users without the required role", () => {
  const res = responseRecorder();
  requireRole("admin")({ user: { role: "user" } }, res, () => {
    assert.fail("next should not be called");
  });

  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { error: "Forbidden" });
});
