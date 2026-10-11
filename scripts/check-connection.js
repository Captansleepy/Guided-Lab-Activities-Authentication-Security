require("dotenv").config();

const assert = require("node:assert/strict");
const mongoose = require("mongoose");
const app = require("../app");

async function checkConnection() {
  let server;
  try {
    if (!process.env.MONGODB_URI || /[<>]/.test(process.env.MONGODB_URI)) {
      throw new Error("Fill MONGODB_URI in .env before checking the connection");
    }
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      throw new Error("Set JWT_SECRET to at least 32 characters in .env");
    }
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10_000 });
    await mongoose.connection.db.command({ ping: 1 });
    server = await new Promise((resolve, reject) => {
      const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
      listener.once("error", reject);
    });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const list = await fetch(`${baseUrl}/api/students`);
    assert.equal(list.status, 200);
    assert.ok(Array.isArray(await list.json()));
    const write = await fetch(`${baseUrl}/api/students`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Nora", major: "IT", score: 88 })
    });
    assert.equal(write.status, 401);
    assert.deepEqual(await write.json(), { error: "No token provided" });
    console.log("Configured MongoDB connection: PASS");
    console.log("Public student GET: 200; unauthenticated POST: 401");
    console.log("Read-only smoke check complete; no records were written.");
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
  }
}

checkConnection().catch((error) => {
  // Connection errors can contain the URI. Report their type without printing credentials.
  console.error(`Connection check failed (${error.name}). Check .env, database credentials and MongoDB network access.`);
  process.exitCode = 1;
});
