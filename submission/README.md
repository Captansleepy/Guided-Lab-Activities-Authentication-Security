# CSC220 Week 9 submission

Repository: https://github.com/Captansleepy/Guided-Lab-Activities-Authentication-Security

For actual Thunder Client interface captures from the configured Atlas database, see [thunder-client/README.md](thunder-client/README.md). That set contains 19 visually verified screenshots. The gallery below is the earlier Newman report evidence.

Verified on 11 October 2026 (Asia/Bangkok): `npm test` passed 30 tests. The actual Postman collection run passed all 24 HTTP requests and 49 assertions. Password hashing was checked directly in a real temporary MongoDB database.

The configured Atlas connection also passed a separate read-only smoke check: public student GET returned 200 and unauthenticated POST returned 401. That check wrote no records.

| Screenshot | Evidence |
| --- | --- |
| [01-summary.png](01-summary.png) | All collection requests and assertions passed |
| [02-registration-login.png](02-registration-login.png) | Register 201 and successful JWT login 200 |
| [03-401-unauthorized.png](03-401-unauthorized.png) | Wrong password, missing/invalid/altered tokens, and protected writes return 401 |
| [04-successful-writes.png](04-successful-writes.png) | Authenticated POST returns 201 and PATCH returns 200 |
| [05-403-forbidden.png](05-403-forbidden.png) | Normal-user DELETE returns 403 |
| [06-admin-delete.png](06-admin-delete.png) | Admin DELETE returns 204 and deleted student returns 404 |
| [07-password-hash.png](07-password-hash.png) | Stored bcrypt hash, cost 10, and comparison with the dummy password |

Open [report.html](report.html) for the complete report or [results.json](results.json) for sanitized recorded requests, responses, and assertions. Actual bearer tokens are redacted. All accounts in these artifacts are dummy test accounts.

The PNGs capture a report from Newman, Postman's collection runner. They are not desktop Postman interface captures. The lab specifically asks for Postman screenshots: if your instructor requires that interface, import the collection and local environment from `postman/`, run against your configured API, and capture the same 401, 403, and success cases in Postman. The password-hash screenshot uses temporary local MongoDB; inspect your Atlas `users` collection after registration to capture Atlas-specific proof.

To reproduce these artifacts, run `npm run evidence`. To check your configured MongoDB connection without changing records, run `npm run check:db`. On Windows, use `npm.cmd` when PowerShell blocks `npm.ps1`.

Submit the GitHub URL and the relevant PNGs on LMS. Keep `.env` and `node_modules/` out of the submission.
