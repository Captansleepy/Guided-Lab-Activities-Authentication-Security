# Authentication and security submission screenshots

Prepared on 11 October 2026 (Asia/Bangkok) using Thunder Client 2.41.7 in VS Code. The screenshots capture requests and responses from the project API at `http://localhost:3100`, connected to the configured MongoDB Atlas database.

All 19 checks returned their expected results. Every listed PNG was visually reviewed to confirm its displayed status and readable request/response evidence in Thunder Client.

| Screenshot | Check | Expected status |
| --- | --- | --- |
| `01-register-201.png` | Register a new test user | 201 |
| `02-duplicate-400.png` | Register the same email again | 400 |
| `03-login-200.png` | Log in with the correct password | 200 |
| `04-wrong-password-401.png` | Log in with an incorrect password | 401 |
| `05-public-list-200.png` | List students without authentication | 200 |
| `06-create-no-token-401.png` | Create a student without a token | 401 |
| `07-invalid-token-401.png` | Create a student with an invalid token | 401 |
| `08-create-with-token-201.png` | Create a student with a valid user token | 201 |
| `09-public-read-200.png` | Read the created student without authentication | 200 |
| `10-patch-no-token-401.png` | Update a student without a token | 401 |
| `11-patch-with-token-200.png` | Update a student with a valid user token | 200 |
| `12-delete-no-token-401.png` | Delete a student without a token | 401 |
| `13-user-delete-403.png` | Delete a student with an ordinary user token | 403 |
| `14-admin-login-200.png` | Log in again after promoting the test user to admin | 200 |
| `15-admin-delete-204.png` | Delete the test student with a new admin token | 204 |
| `16-deleted-not-found-404.png` | Read the deleted student | 404 |
| `17-me-user-200.png` | Inspect the identity associated with the original user token | 200 |
| `18-altered-token-401.png` | Use an altered token | 401 |
| `19-me-admin-200.png` | Inspect the identity associated with the new admin token | 200 |

The capture session used a dedicated temporary JWT secret on port 3100; the original API on port 3000 is unchanged. Only a unique dummy user and student fixtures were used. The dummy user's database role was promoted to admin, followed by a new login to obtain the admin token. The test fixtures were removed and the temporary capture server was stopped after the session, invalidating the screenshot tokens.

`atlas-password-proof.json` records sanitized selected fields from the actual dummy user document queried before promotion. Its password was a bcrypt hash with cost 10; bcrypt comparison with the dummy password passed, and plaintext was not stored. The stored hash is redacted, and no connection credentials are included.

Thunder Client was selected by the user. The lab specifies Postman screenshots, so confirm that the instructor accepts Thunder Client captures. These files provide API evidence; they do not include an Atlas interface screenshot of the stored password hash.
