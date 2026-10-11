# CSC220 Week 9: Authentication and Security

Express and MongoDB implementation of the Week 9 guided lab. It includes user registration/login, bcrypt password hashing, JWT authentication, public student reads, authenticated student creation/updates, and admin-only student deletion.

## Setup

1. Install Node.js 18 or later.
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

Run the automated middleware tests with `npm test`.
