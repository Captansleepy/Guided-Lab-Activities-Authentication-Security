# CSC220 Week 9: Authentication and Security

Express and MongoDB implementation of the Week 9 guided lab. It includes user registration/login, bcrypt password hashing, JWT authentication, public student reads, authenticated student creation/updates, and admin-only student deletion.

## Setup

1. Install Node.js 20.19 or later.
2. Copy `.env.example` to `.env` (in PowerShell, run `Copy-Item .env.example .env`).
3. In `.env`, set `MONGODB_URI` to the Atlas connection string, replacing the username and password placeholders with your Atlas database credentials. Include a database name in the URL, such as `student_api`. Do not commit `.env`.
4. Set `JWT_SECRET` to a unique random value of at least 32 characters. Do not reuse your MongoDB password.
5. In MongoDB Atlas, allow network access from the machine running the API and ensure the database user has read/write access.
6. Install dependencies and start the API:

   ```sh
   npm install
   npm run dev
   ```

The server listens on port `3000` unless `PORT` is set.

Run `npm run check:db` to verify your configured database connection, a public GET, and a rejected unauthenticated POST without writing any records.

## API

| Method | Path | Access | Behavior |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | Public | Create a user; role defaults to `user` |
| POST | `/api/auth/login` | Public | Verify credentials and return a one-hour JWT |
| GET | `/api/auth/me` | Bearer token | Return the authenticated user's id and role |
| GET | `/api/students` | Public | List students |
| GET | `/api/students/:id` | Public | Read one student |
| POST | `/api/students` | Bearer token | Create a student |
| PATCH | `/api/students/:id` | Bearer token | Update student fields |
| DELETE | `/api/students/:id` | Admin bearer token | Delete a student |

Student records require `name`, `major`, and numeric `score` (0–100). Send authenticated requests with:

```http
Authorization: Bearer <token>
```

Registration accepts an email and a password of at least eight characters. It never accepts a role from the request, and the password is hashed before it is saved. To test admin deletion, promote a test user's `role` to `admin` in the MongoDB `users` collection, then log in again to get a token containing the updated role.

## Postman checks

1. Register with `POST /api/auth/register` and JSON such as `{"email":"student1@example.com","password":"password123"}`. Expect `201`; the response does not include the password.
2. Log in with `POST /api/auth/login` using the same credentials. Expect `200` with a token. A wrong password returns `401`.
3. Try `POST /api/students` without a token; expect `401`. Repeat with the bearer token and a body such as `{"name":"Nora","major":"IT","score":88}`; expect `201`.
4. Check that `GET /api/students` is public and that PATCH requires a valid bearer token.
5. Try DELETE with a normal-user token; expect `403`. Promote a test user in Atlas, log in again, and retry with the new admin token; expect `204`.
6. An invalid token returns `401`; `/api/auth/me` returns the authenticated user's id and role.

## Automated verification

Run `npm test` for the middleware and real HTTP integration tests. The integration tests start a disposable local MongoDB database, verify password hashes in stored documents, and exercise registration, login, public reads, protected writes, validation, and admin deletion. They do not use `.env` or modify your Atlas database. The first run downloads a MongoDB binary into the ignored `.cache/` directory and requires internet access.

For just the middleware checks, run `npm run test:middleware`.

## Postman collection and submission evidence

Import `postman/CSC220-Week9.postman_collection.json` and `postman/Local.postman_environment.json` into Postman. Start the API, select the local environment, and run the requests in order against a fresh lab database. Change the collection's `email` before repeating the run so the first registration can succeed. Set `adminEmail` and `adminPassword` to an existing test account you have promoted to `admin` in MongoDB. The collection saves the login tokens and student ID automatically.

Run `npm run evidence` to execute the same 24-request Postman collection with Newman against a temporary real MongoDB database and generate `submission/report.html`, sanitized JSON results, and PNG screenshots. The runner seeds a dummy admin account only in that temporary database. It uses an installed Chrome or Edge browser; set `CHROME_PATH` if your browser is elsewhere. On Windows PowerShell, use `npm.cmd` if execution policy blocks `npm.ps1`.

See `submission/README.md` for the submission checklist and screenshots. These are screenshots of an actual Newman/Postman collection report. The lab specifically requests Postman screenshots; if your instructor requires the desktop Postman interface, use the included collection to capture those after configuring Atlas. The stored-password screenshot proves hashing in the temporary MongoDB database; check the `users` collection in Atlas after running with your own URI.

Actual Thunder Client interface screenshots from a completed Atlas test session are also available in `submission/thunder-client/`. All 19 pictured checks passed, including 401, 403, authenticated creation and updates, and admin deletion. The capture server used port 3100 and a temporary JWT secret; its dummy records were removed after testing. `atlas-password-proof.json` contains sanitized selected database fields and the bcrypt comparison result for that dummy user; the stored hash is redacted.

Never commit `.env`, real database credentials, or real bearer tokens. The checked-in evidence uses dummy lab accounts and redacts JWTs.

The production dependency audit (`npm audit --omit=dev`) reported zero vulnerabilities during verification. Newman 6.2.3 still has upstream advisories in its development-only dependency tree; patched compatible dependencies are pinned through `overrides` in `package.json`.
