const fs = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { pathToFileURL } = require("node:url");

const root = path.resolve(__dirname, "..");
const outputDir = path.join(root, "submission");

// Set this before importing mongodb-memory-server so its cache stays in this workspace.
process.env.MONGOMS_DOWNLOAD_DIR = path.join(root, ".cache", "mongodb-binaries");
const { MongoMemoryServer } = require("mongodb-memory-server");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const newman = require("newman");
const { chromium } = require("playwright-core");
const app = require("../app");
const User = require("../models/User");

function redact(value, key = "") {
  if (/^(token|userToken|adminToken|JWT_SECRET)$/i.test(key)) return "[redacted JWT]";
  if (Array.isArray(value)) return value.map((item) => redact(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redact(item, name)]));
  }
  if (typeof value !== "string") return value;
  return value
    .replace(/Bearer\s+[^\s"<>]+/gi, "Bearer [redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted JWT]");
}

function readableBody(text) {
  if (!text) return null;
  try {
    return redact(JSON.parse(text));
  } catch {
    return redact(text);
  }
}

function executionRecord(execution) {
  const request = execution.request;
  const response = execution.response;
  const headers = request.headers.all().filter((header) =>
    ["authorization", "content-type"].includes(header.key.toLowerCase())
  );
  return {
    name: execution.item.name,
    request: {
      method: request.method,
      url: redact(request.url.toString()),
      headers: Object.fromEntries(headers.map((header) => [header.key, redact(header.value)])),
      body: readableBody(request.body?.raw)
    },
    response: response ? {
      code: response.code,
      status: response.status,
      responseTimeMs: response.responseTime,
      body: readableBody(response.text())
    } : null,
    assertions: (execution.assertions || []).map((assertion) => ({
      name: assertion.assertion,
      passed: !assertion.error,
      ...(assertion.error ? { error: redact(assertion.error.message) } : {})
    })),
    ...(execution.requestError ? { error: redact(execution.requestError.message) } : {})
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[character]));
}

function bodyHtml(body) {
  return escapeHtml(body === null ? "(empty body)" : typeof body === "string" ? body : JSON.stringify(body, null, 2));
}

function requestCard(record) {
  const status = record.response?.code || "ERROR";
  const passed = record.response && !record.error && record.assertions.every((assertion) => assertion.passed);
  return `<article class="request-card">
    <div class="card-top"><h3>${escapeHtml(record.name)}</h3><span class="status ${passed ? "pass" : "fail"}">${escapeHtml(status)}</span></div>
    <div class="endpoint"><strong>${escapeHtml(record.request.method)}</strong> ${escapeHtml(record.request.url)}</div>
    <div class="payloads"><div><h4>Request</h4><pre>${bodyHtml({ headers: record.request.headers, body: record.request.body })}</pre></div>
    <div><h4>Actual response · ${record.response?.responseTimeMs ?? "?"} ms</h4><pre>${bodyHtml(record.response?.body ?? record.error ?? null)}</pre></div></div>
    <ul class="assertions">${record.assertions.map((assertion) => `<li class="${assertion.passed ? "pass-text" : "fail-text"}">${assertion.passed ? "PASS" : "FAIL"} · ${escapeHtml(assertion.name)}${assertion.error ? ` — ${escapeHtml(assertion.error)}` : ""}</li>`).join("")}</ul>
  </article>`;
}

function evidenceSection(id, title, description, records, report) {
  return `<section class="evidence" id="${id}"><div class="section-kicker">CSC220 · Week 9 · Actual API execution</div>
    <h2>${title}</h2><p class="description">${description}</p>
    <p class="timestamp">${escapeHtml(report.recordedAtBangkok)} · Newman ${escapeHtml(report.runner.version)} · Temporary local MongoDB</p>
    <div class="card-grid">${records.map(requestCard).join("") || '<p>No matching requests were executed.</p>'}</div>
    <p class="footnote">Request and response values come from the completed Postman collection run. JWT values are redacted.</p></section>`;
}

function reportHtml(report) {
  const rows = report.executions;
  const auth = rows.filter((row) => /\/api\/auth\/(register|login)/.test(row.request.url) && [200, 201].includes(row.response?.code));
  const unauthorized = rows.filter((row) => row.response?.code === 401);
  const writes = rows.filter((row) => /\/api\/students/.test(row.request.url) && ["POST", "PATCH", "PUT"].includes(row.request.method) && [200, 201].includes(row.response?.code));
  const forbidden = rows.filter((row) => row.response?.code === 403);
  const deletion = rows.filter((row) => (row.request.method === "DELETE" && row.response?.code === 204) || (/\/api\/students/.test(row.request.url) && row.response?.code === 404));
  const proof = report.passwordStorage;
  const statusRows = rows.map((row) => `<tr><td>${escapeHtml(row.name)}</td><td>${escapeHtml(row.request.method)}</td><td>${row.response?.code ?? "ERROR"}</td><td class="${row.assertions.every((assertion) => assertion.passed) && !row.error ? "pass-text" : "fail-text"}">${row.assertions.filter((assertion) => assertion.passed).length}/${row.assertions.length} passed</td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CSC220 Authentication & Security — Test Evidence</title>
    <style>
      *{box-sizing:border-box}body{margin:0;background:#e9eef5;color:#192c42;font:16px/1.5 Arial,Helvetica,sans-serif}main{max-width:1320px;margin:32px auto;padding:0 24px 32px}.evidence{background:white;border:1px solid #d7e0eb;border-radius:18px;padding:32px;margin:24px 0;box-shadow:0 6px 24px #233b5910}.section-kicker{color:#436384;font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}h1{font-size:34px;line-height:1.2;margin:10px 0 14px}h2{font-size:28px;line-height:1.2;margin:8px 0 12px}h3{font-size:17px;line-height:1.35;margin:0}h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#4d6279;margin:0 0 8px}.description{color:#425a73;margin:0 0 10px}.timestamp,.footnote{font-size:12px;color:#60758a}.timestamp{margin:0 0 24px}.footnote{margin:22px 0 0}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:22px 0}.metric{background:#f1f6fc;border:1px solid #dce7f3;padding:14px 18px;border-radius:10px}.metric strong{display:block;font-size:28px}.metric span{font-size:12px;color:#50667e}.pass-text{color:#08754f}.fail-text{color:#b32936}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #e5ebf3;padding:9px 8px;text-align:left}th{color:#536b84;font-size:11px;text-transform:uppercase}td:first-child{width:66%}.card-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.request-card{border:1px solid #d9e3ef;border-radius:12px;padding:18px;background:#fbfdff;min-width:0}.card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.status{display:inline-block;border-radius:6px;padding:3px 9px;font-size:14px;font-weight:bold;flex-shrink:0}.status.pass{background:#dff6ed;color:#096b4d}.status.fail{background:#ffe5e8;color:#af2936}.endpoint{font-family:Consolas,monospace;font-size:12px;overflow-wrap:anywhere;background:#eaf1fa;padding:9px;border-radius:6px;margin:13px 0}.endpoint strong{color:#24649a}.payloads{display:grid;grid-template-columns:1fr;gap:10px}pre{font:12px/1.55 Consolas,"Courier New",monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin:0;border-radius:7px;background:#edf2f8;padding:12px;color:#20394f}.assertions{list-style:none;padding:0;margin:13px 0 0;font-size:12px}.assertions li{margin-top:5px}.note{border-left:4px solid #3884bc;background:#edf5fc;padding:12px 16px;font-size:13px;color:#325675;margin:18px 0}.hash-proof{display:grid;grid-template-columns:1.15fr 1fr;gap:20px}.hash-checks{padding:20px;background:#ecf8f2;border-radius:10px}.hash-checks p{margin:0 0 12px}.hash-checks p:last-child{margin:0}.links{display:flex;flex-wrap:wrap;gap:10px;font-size:12px;margin-top:18px}a{color:#256597}.badge{background:${report.success ? "#def5e9" : "#ffe5e8"};color:${report.success ? "#096b4d" : "#af2936"};padding:7px 12px;border-radius:8px;font-weight:bold;display:inline-block}.overview-sub{font-size:17px;color:#4e657e} @media(max-width:900px){.card-grid,.hash-proof{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}
    </style></head><body><main>
    <section class="evidence" id="summary"><div class="section-kicker">CSC220 · Week 9 · Submission evidence</div><h1>Authentication & Security</h1>
      <p class="overview-sub">Postman collection executed with the Newman command-line runner</p><span class="badge">${report.success ? "ALL CHECKS PASSED" : "CHECKS FAILED"}</span>
      <p class="timestamp" style="margin-top:12px">${escapeHtml(report.recordedAtBangkok)} · ${escapeHtml(report.collectionName)}</p>
      <div class="metrics"><div class="metric"><strong>${report.stats.requests}</strong><span>HTTP requests</span></div><div class="metric"><strong>${report.stats.assertions}</strong><span>Postman assertions</span></div><div class="metric"><strong>${report.stats.failedAssertions}</strong><span>Failed assertions</span></div><div class="metric"><strong>${proof.passwordMatches ? "PASS" : "FAIL"}</strong><span>MongoDB bcrypt verification</span></div></div>
      <div class="note">These results were captured from this repository's Express app, real HTTP requests and a disposable local MongoDB server. No Atlas database or .env credentials were used. This report renders saved execution evidence; it is not a Postman application screenshot.</div>
      <table><thead><tr><th>Executed request</th><th>Method</th><th>HTTP</th><th>Assertions</th></tr></thead><tbody>${statusRows}</tbody></table>
      <div class="links"><a href="results.json">Saved execution JSON</a><a href="#registration-login">Registration & login</a><a href="#unauthorized">401 evidence</a><a href="#writes">Authorized writes</a><a href="#forbidden">403 evidence</a><a href="#admin-delete">Admin delete</a><a href="#password-hash">MongoDB password hash</a></div>
    </section>
    ${evidenceSection("registration-login", "Registration & login", "The public register route creates a regular user. Successful login returns a signed JWT for each account.", auth, report)}
    ${evidenceSection("unauthorized", "401 · Authentication required", "Requests without valid authentication are rejected by the running API.", unauthorized, report)}
    ${evidenceSection("writes", "Authenticated POST & PATCH", "The collection uses the regular user's login token to create and update a student record.", writes, report)}
    ${evidenceSection("forbidden", "403 · Admin permission required", "A regular user's authenticated request cannot perform the admin-only deletion.", forbidden, report)}
    ${evidenceSection("admin-delete", "Admin deletion & database outcome", "The admin's login token permits deletion. The follow-up request checks the deleted resource.", deletion, report)}
    <section class="evidence" id="password-hash"><div class="section-kicker">CSC220 · Week 9 · Actual database evidence</div><h2>MongoDB stores a bcrypt hash</h2>
      <p class="description">The runner reads the registered user directly from the temporary MongoDB database through Mongoose.</p><p class="timestamp">${escapeHtml(report.recordedAtBangkok)} · Database: csc220_evidence</p>
      <div class="hash-proof"><div><h4>Executed database query</h4><pre>User.findOne({ email: "student1@example.com" })\n  .select("+password")\n  .lean()</pre><h4 style="margin-top:18px">Actual stored document (selected fields)</h4><pre>${bodyHtml({ _id: proof.id, email: proof.email, role: proof.role, password: proof.passwordHash })}</pre></div>
      <div class="hash-checks"><h3 style="margin-bottom:20px">Verified against the stored password</h3><p class="${proof.passwordMatches ? "pass-text" : "fail-text"}"><strong>${proof.passwordMatches ? "PASS" : "FAIL"}</strong> · bcrypt.compare("password123", storedHash)</p><p class="${proof.isBcrypt ? "pass-text" : "fail-text"}"><strong>${proof.isBcrypt ? "PASS" : "FAIL"}</strong> · Stored value is a bcrypt hash</p><p class="${!proof.plaintextStored ? "pass-text" : "fail-text"}"><strong>${!proof.plaintextStored ? "PASS" : "FAIL"}</strong> · Plaintext password is not stored</p><p>Bcrypt cost: <strong>${proof.cost}</strong></p><p>Account role: <strong>${escapeHtml(proof.role)}</strong></p><p>Sample password is a dummy lab credential.</p></div></div><p class="footnote">This hash belongs only to the disposable test account. The local database is stopped and discarded after this run.</p>
    </section></main></body></html>`;
}

async function captureScreenshots(reportPath) {
  const candidates = [
    process.env.CHROME_PATH,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
  ].filter(Boolean);
  let executablePath;
  for (const candidate of candidates) {
    try { await fs.access(candidate); executablePath = candidate; break; } catch { /* Try the next location. */ }
  }
  if (!executablePath) throw new Error("Chrome or Edge was not found. Set CHROME_PATH to your browser executable and rerun npm run evidence.");
  let browser;
  try {
    browser = await chromium.launch({ executablePath, headless: true });
    const page = await browser.newPage({ viewport: { width: 1400, height: 1000 }, deviceScaleFactor: 1 });
    await page.goto(pathToFileURL(reportPath).href);
    await page.evaluate(() => document.fonts.ready);
    const screenshots = [
      ["summary", "01-summary.png"],
      ["registration-login", "02-registration-login.png"],
      ["unauthorized", "03-401-unauthorized.png"],
      ["writes", "04-successful-writes.png"],
      ["forbidden", "05-403-forbidden.png"],
      ["admin-delete", "06-admin-delete.png"],
      ["password-hash", "07-password-hash.png"]
    ];
    for (const [id, file] of screenshots) {
      await page.locator(`#${id}`).screenshot({ path: path.join(outputDir, file) });
      console.log(`Saved submission/${file}`);
    }
  } finally {
    if (browser) await browser.close();
  }
}

async function main() {
  const collectionPath = path.join(root, "postman", "CSC220-Week9.postman_collection.json");
  const collection = JSON.parse(await fs.readFile(collectionPath, "utf8"));
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = crypto.randomBytes(48).toString("hex");
  let mongo;
  let server;
  try {
    await fs.mkdir(outputDir, { recursive: true });
    mongo = await MongoMemoryServer.create({ instance: { dbName: "csc220_evidence" } });
    await mongoose.connect(mongo.getUri("csc220_evidence"));
    await User.init();
    await User.create({ email: "admin@example.com", password: "password123", role: "admin" });
    server = await new Promise((resolve, reject) => {
      const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
      listener.once("error", reject);
    });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const values = {
      baseUrl,
      email: "student1@example.com",
      password: "password123",
      adminEmail: "admin@example.com",
      adminPassword: "password123",
      userToken: "",
      adminToken: "",
      alteredToken: "",
      studentId: ""
    };
    // Scripts set pm.collectionVariables; an environment entry would shadow those updates.
    const runCollection = structuredClone(collection);
    runCollection.variable = Object.entries(values).map(([key, value]) => ({ key, value }));
    console.log(`Executing the Postman collection against ${baseUrl} and disposable MongoDB.`);
    const summary = await new Promise((resolve, reject) => {
      newman.run({
        collection: runCollection,
        reporters: ["cli"],
        timeoutRequest: 10_000,
        timeoutScript: 10_000
      }, (error, result) => error ? reject(error) : resolve(result));
    });
    const user = await User.findOne({ email: values.email }).select("+password").lean();
    if (!user) throw new Error("The collection did not register student1@example.com; database evidence cannot be generated.");
    const passwordMatches = await bcrypt.compare(values.password, user.password);
    const isBcrypt = /^\$2[aby]\$\d{2}\$/.test(user.password);
    const stats = summary.run.stats;
    const now = new Date();
    const report = {
      recordedAt: now.toISOString(),
      recordedAtBangkok: new Intl.DateTimeFormat("en-GB", { dateStyle: "long", timeStyle: "long", timeZone: "Asia/Bangkok" }).format(now),
      timezone: "Asia/Bangkok",
      collectionName: collection.info.name,
      runner: { name: "Newman / Postman collection runner", version: require("newman/package.json").version },
      database: { kind: "Disposable local MongoDB", name: "csc220_evidence", atlasUsed: false },
      stats: {
        requests: stats.requests.total,
        failedRequests: stats.requests.failed,
        assertions: stats.assertions.total,
        failedAssertions: stats.assertions.failed,
        durationMs: summary.run.timings.completed - summary.run.timings.started
      },
      executions: summary.run.executions.map(executionRecord),
      failures: (summary.run.failures || []).map((failure) => ({
        source: failure.source?.name || "Collection run",
        message: redact(failure.error?.message || String(failure.error))
      })),
      passwordStorage: {
        id: String(user._id),
        email: user.email,
        role: user.role,
        passwordHash: user.password,
        isBcrypt,
        cost: isBcrypt ? bcrypt.getRounds(user.password) : null,
        passwordMatches,
        plaintextStored: user.password === values.password
      }
    };
    report.success = report.failures.length === 0 && report.stats.failedRequests === 0 && report.stats.failedAssertions === 0 && passwordMatches && isBcrypt && !report.passwordStorage.plaintextStored;
    await fs.writeFile(path.join(outputDir, "results.json"), JSON.stringify(redact(report), null, 2) + "\n");
    const reportPath = path.join(outputDir, "report.html");
    await fs.writeFile(reportPath, reportHtml(report));
    await captureScreenshots(reportPath);
    console.log(`Evidence complete: ${report.stats.requests} requests, ${report.stats.assertions} assertions, ${report.stats.failedAssertions} failed assertions.`);
    if (!report.success) throw new Error("Evidence checks failed. Review submission/results.json and submission/report.html.");
  } finally {
    const cleanupErrors = [];
    try {
      if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    } catch (error) { cleanupErrors.push(error); }
    try { await mongoose.disconnect(); } catch (error) { cleanupErrors.push(error); }
    try { if (mongo) await mongo.stop(); } catch (error) { cleanupErrors.push(error); }
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
    if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Evidence resources could not all be closed.");
  }
}

main().catch((error) => {
  console.error(redact(error.stack || error.message));
  process.exitCode = 1;
});
