const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");

const app = require("../app");
const User = require("../models/User");

test("authentication and student API with a disposable MongoDB database", { timeout: 300_000 }, async (t) => {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = "integration-test-secret-for-disposable-local-database";
  let mongo;
  let server;

  try {
    mongo = await MongoMemoryServer.create({
      binary: {
        downloadDir: path.join(__dirname, "..", ".cache", "mongodb-binaries")
      },
      instance: { dbName: "csc220_test" }
    });
    await mongoose.connect(mongo.getUri("csc220_test"));
    await User.init();
    server = await new Promise((resolve, reject) => {
      const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
      listener.once("error", reject);
    });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    async function request(method, route, { body, rawBody, token } = {}) {
      const headers = {};
      if (token !== undefined) headers.authorization = `Bearer ${token}`;
      if (body !== undefined || rawBody !== undefined) headers["content-type"] = "application/json";
      const response = await fetch(`${baseUrl}${route}`, {
        method,
        headers,
        body: rawBody !== undefined ? rawBody : body !== undefined ? JSON.stringify(body) : undefined
      });
      const text = await response.text();
      return {
        status: response.status,
        body: text.length ? JSON.parse(text) : undefined
      };
    }

    const email = "student@example.com";
    const password = "CourseWork10!strong";
    let userId;
    let userToken;
    let adminToken;
    let studentId;

    await t.test("registration normalizes email, hashes password, and ignores requested admin role", async () => {
      const response = await request("POST", "/api/auth/register", {
        body: { email: "  Student@Example.COM  ", password, role: "admin" }
      });
      assert.equal(response.status, 201);
      assert.equal(response.body.email, email);
      assert.equal(response.body.role, "user");
      assert.equal(Object.hasOwn(response.body, "password"), false);
      assert.ok(mongoose.isValidObjectId(response.body.id));
      userId = response.body.id;

      const stored = await User.findById(userId).select("+password").lean();
      assert.equal(stored.email, email);
      assert.equal(stored.role, "user");
      assert.notEqual(stored.password, password);
      assert.equal(await bcrypt.compare(password, stored.password), true);
      assert.equal(bcrypt.getRounds(stored.password), 10);
      const publicUser = await User.findById(userId).lean();
      assert.equal(Object.hasOwn(publicUser, "password"), false);
    });

    await t.test("duplicate normalized email is rejected without creating another account", async () => {
      const response = await request("POST", "/api/auth/register", {
        body: { email: "STUDENT@example.com", password }
      });
      assert.equal(response.status, 400);
      assert.deepEqual(response.body, { error: "Email already registered" });
      assert.equal(await User.countDocuments({ email }), 1);
    });

    await t.test("registration rejects missing, malformed, short, and oversized password input", async () => {
      const invalidInputs = [
        {},
        { email },
        { password },
        { email: 42, password },
        { email, password: 42 },
        { email: "invalid-address", password },
        { email, password: "short" },
        { email, password: "a".repeat(73) },
        { email, password: "😀".repeat(25) }
      ];
      for (const body of invalidInputs) {
        const response = await request("POST", "/api/auth/register", { body });
        assert.equal(response.status, 400, `input should be rejected: ${JSON.stringify(body)}`);
        assert.equal(typeof response.body.error, "string");
      }
    });

    await t.test("the bcrypt 72-byte boundary works and login rejects a longer alias", async () => {
      const boundaryPassword = "a".repeat(72);
      const boundaryEmail = "boundary@example.com";
      const registered = await request("POST", "/api/auth/register", {
        body: { email: boundaryEmail, password: boundaryPassword }
      });
      assert.equal(registered.status, 201);
      const loggedIn = await request("POST", "/api/auth/login", {
        body: { email: boundaryEmail, password: boundaryPassword }
      });
      assert.equal(loggedIn.status, 200);
      const truncatedAlias = await request("POST", "/api/auth/login", {
        body: { email: boundaryEmail, password: `${boundaryPassword}different` }
      });
      assert.equal(truncatedAlias.status, 401);
    });

    await t.test("login accepts normalized email and returns a verifiable one-hour user JWT", async () => {
      const response = await request("POST", "/api/auth/login", {
        body: { email: "  STUDENT@EXAMPLE.COM  ", password }
      });
      assert.equal(response.status, 200);
      assert.equal(typeof response.body.token, "string");
      assert.equal(Object.hasOwn(response.body, "password"), false);
      userToken = response.body.token;
      const claims = jwt.verify(userToken, process.env.JWT_SECRET);
      assert.equal(claims.id, userId);
      assert.equal(claims.role, "user");
      assert.equal(claims.exp - claims.iat, 3600);
      const me = await request("GET", "/api/auth/me", { token: userToken });
      assert.equal(me.status, 200);
      assert.deepEqual(me.body, { id: userId, role: "user" });
    });

    await t.test("login uses the same 401 response for wrong password and unknown email", async () => {
      const wrongPassword = await request("POST", "/api/auth/login", {
        body: { email, password: "wrong-password" }
      });
      const unknownEmail = await request("POST", "/api/auth/login", {
        body: { email: "unknown@example.com", password }
      });
      assert.equal(wrongPassword.status, 401);
      assert.equal(unknownEmail.status, 401);
      assert.deepEqual(wrongPassword.body, { error: "Invalid credentials" });
      assert.deepEqual(unknownEmail.body, wrongPassword.body);
      const missingCredentials = await request("POST", "/api/auth/login", { body: {} });
      assert.equal(missingCredentials.status, 400);
    });

    await t.test("the public student list works without authentication", async () => {
      const response = await request("GET", "/api/students");
      assert.equal(response.status, 200);
      assert.deepEqual(response.body, []);
    });

    await t.test("missing credentials deny protected create, update, delete, and profile routes", async () => {
      const missingId = new mongoose.Types.ObjectId().toString();
      const routes = [
        ["POST", "/api/students", { name: "Missing Token", major: "CS", score: 80 }],
        ["PATCH", `/api/students/${missingId}`, { score: 90 }],
        ["DELETE", `/api/students/${missingId}`, undefined],
        ["GET", "/api/auth/me", undefined]
      ];
      for (const [method, route, body] of routes) {
        const response = await request(method, route, { body });
        assert.equal(response.status, 401, `${method} ${route}`);
      }
    });

    await t.test("authenticated create saves trimmed student fields and public GET reads them", async () => {
      const created = await request("POST", "/api/students", {
        token: userToken,
        body: { name: "  Ada Lovelace  ", major: "  Computer Science  ", score: 85 }
      });
      assert.equal(created.status, 201);
      assert.equal(created.body.name, "Ada Lovelace");
      assert.equal(created.body.major, "Computer Science");
      assert.equal(created.body.score, 85);
      studentId = created.body._id;
      assert.ok(mongoose.isValidObjectId(studentId));
      const detail = await request("GET", `/api/students/${studentId}`);
      assert.equal(detail.status, 200);
      assert.deepEqual(detail.body, created.body);
      const list = await request("GET", "/api/students");
      assert.equal(list.status, 200);
      assert.equal(list.body.length, 1);
      assert.equal(list.body[0]._id, studentId);
    });

    await t.test("authenticated create validates fields and score range", async () => {
      const invalidInputs = [
        {},
        { name: "Ada", score: 80 },
        { name: " ", major: "CS", score: 80 },
        { name: "Ada", major: "CS", score: "80" },
        { name: "Ada", major: "CS", score: -1 },
        { name: "Ada", major: "CS", score: 101 },
        { name: "Ada", major: "CS", score: 80, role: "admin" },
        []
      ];
      for (const body of invalidInputs) {
        const response = await request("POST", "/api/students", { token: userToken, body });
        assert.equal(response.status, 400, `input should be rejected: ${JSON.stringify(body)}`);
      }
      const list = await request("GET", "/api/students");
      assert.equal(list.body.length, 1);
    });

    await t.test("authenticated PATCH updates only submitted fields", async () => {
      const response = await request("PATCH", `/api/students/${studentId}`, {
        token: userToken,
        body: { name: "  Ada Updated  ", score: 92 }
      });
      assert.equal(response.status, 200);
      assert.equal(response.body.name, "Ada Updated");
      assert.equal(response.body.major, "Computer Science");
      assert.equal(response.body.score, 92);
      const persisted = await request("GET", `/api/students/${studentId}`);
      assert.equal(persisted.body.score, 92);
    });

    await t.test("PATCH rejects empty, unknown, mistyped, and out-of-range changes", async () => {
      for (const body of [{}, { unknown: true }, { major: " " }, { score: "92" }, { score: -1 }, { score: 101 }]) {
        const response = await request("PATCH", `/api/students/${studentId}`, { token: userToken, body });
        assert.equal(response.status, 400, `input should be rejected: ${JSON.stringify(body)}`);
      }
      const unchanged = await request("GET", `/api/students/${studentId}`);
      assert.equal(unchanged.body.name, "Ada Updated");
      assert.equal(unchanged.body.score, 92);
    });

    await t.test("invalid, expired, and tampered JWTs return 401", async () => {
      const expired = jwt.sign({ id: userId, role: "user" }, process.env.JWT_SECRET, { expiresIn: -1 });
      const parts = userToken.split(".");
      const changedClaims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      changedClaims.role = "admin";
      parts[1] = Buffer.from(JSON.stringify(changedClaims)).toString("base64url");
      const tampered = parts.join(".");
      for (const token of ["invalid", expired, tampered, `${userToken} extra`]) {
        const response = await request("GET", "/api/auth/me", { token });
        assert.equal(response.status, 401);
      }
    });

    await t.test("malformed JSON returns 400 and oversized JSON returns 413", async () => {
      const malformed = await request("POST", "/api/auth/register", { rawBody: '{"email":' });
      assert.equal(malformed.status, 400);
      assert.deepEqual(malformed.body, { error: "Invalid JSON body" });
      const oversized = await request("POST", "/api/auth/register", {
        body: { email, password: "a".repeat(150 * 1024) }
      });
      assert.equal(oversized.status, 413);
      assert.equal(typeof oversized.body.error, "string");
    });

    await t.test("a regular user cannot delete a student", async () => {
      const response = await request("DELETE", `/api/students/${studentId}`, { token: userToken });
      assert.equal(response.status, 403);
      assert.deepEqual(response.body, { error: "Forbidden" });
      const preserved = await request("GET", `/api/students/${studentId}`);
      assert.equal(preserved.status, 200);
    });

    await t.test("admin rights come from database promotion and a fresh login", async () => {
      await User.updateOne({ _id: userId }, { $set: { role: "admin" } });
      const login = await request("POST", "/api/auth/login", { body: { email, password } });
      assert.equal(login.status, 200);
      adminToken = login.body.token;
      const claims = jwt.verify(adminToken, process.env.JWT_SECRET);
      assert.equal(claims.role, "admin");
      const me = await request("GET", "/api/auth/me", { token: adminToken });
      assert.deepEqual(me.body, { id: userId, role: "admin" });
      const deleted = await request("DELETE", `/api/students/${studentId}`, { token: adminToken });
      assert.equal(deleted.status, 204);
      assert.equal(deleted.body, undefined);
      const gone = await request("GET", `/api/students/${studentId}`);
      assert.equal(gone.status, 404);
      const list = await request("GET", "/api/students");
      assert.deepEqual(list.body, []);
    });

    await t.test("invalid student IDs return 400 and absent students return 404", async () => {
      const missingId = new mongoose.Types.ObjectId().toString();
      for (const method of ["GET", "PATCH", "DELETE"]) {
        const options = { token: adminToken, body: method === "PATCH" ? { score: 50 } : undefined };
        const invalid = await request(method, "/api/students/not-an-object-id", options);
        assert.equal(invalid.status, 400, `${method} invalid ID`);
        const absent = await request(method, `/api/students/${missingId}`, options);
        assert.equal(absent.status, 404, `${method} absent ID`);
        assert.deepEqual(absent.body, { error: "Student not found" });
      }
      const unknownRoute = await request("GET", "/api/not-a-route");
      assert.equal(unknownRoute.status, 404);
      assert.deepEqual(unknownRoute.body, { error: "Route not found" });
    });
  } finally {
    if (server) {
      await new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
    }
    await mongoose.disconnect();
    if (mongo) await mongo.stop();
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  }
});
