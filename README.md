# RecallOps Node Backend

This service owns authentication, provider credentials, repository imports,
project mappings, provider health, and the continuous monitoring scheduler for
RecallOps.

It sits between the browser and external providers. GitHub, Vercel, and Render
tokens are encrypted per user before being stored. The service sends a
short-lived RecallOps JWT to the Python backend when a deployment inspection is
required.

## Responsibilities

- Register and authenticate local users
- Verify Firebase/GitHub sign-in
- Issue RecallOps JWTs
- Encrypt Vercel, Render, and GitHub credentials with AES-256-GCM
- Persist encrypted credential copies in Firestore
- Discover GitHub repositories available to the current user
- Import monitored repositories
- Discover and map Vercel projects and Render services
- Expose provider and deployment health
- Poll GitHub for new commits
- Trigger Python remediation syncs for tracked providers
- Store repository, connection, and workflow state in SQLite

## Requirements

- Node.js 20-24
- npm
- Firebase project with Authentication and Firestore
- Python backend available locally or over HTTPS
- GitHub access token supplied by Firebase sign-in
- Optional Vercel and Render credentials for deployment monitoring

## Setup

```powershell
npm install
Copy-Item .env.example .env
npm run dev
```

The API starts on `http://localhost:4000` by default.

Run tests with:

```powershell
npm test
```

## Environment variables

| Variable | Purpose |
| --- | --- |
| `NODE_ENV` | `development`, `test`, or `production` |
| `NODE_PORT` | Local listening port; Azure may provide `PORT` |
| `NODE_DATABASE_PATH` | SQLite file used for users and integration state |
| `NODE_CORS_ORIGINS` | Comma-separated allowed frontend origins |
| `AUTH_JWT_SECRET` | Signs RecallOps JWTs; must match the Python backend |
| `CREDENTIAL_ENCRYPTION_KEY` | Independent secret used to encrypt provider tokens |
| `FRONTEND_URL` | Browser URL used after provider callbacks |
| `PYTHON_BACKEND_URL` | Python agent API base URL |
| `MONITOR_INTERVAL_MS` | Enables the monitor when greater than zero |
| `VERCEL_CLIENT_ID` | Sign in with Vercel application client ID |
| `VERCEL_CLIENT_SECRET` | Sign in with Vercel application secret |
| `VERCEL_CALLBACK_URL` | Exact registered Vercel callback URL |
| `VERCEL_SCOPES` | OAuth identity scopes |
| `FIREBASE_PROJECT_ID` | Firebase Admin project ID |
| `FIREBASE_CLIENT_EMAIL` | Firebase Admin service account email |
| `FIREBASE_PRIVATE_KEY` | Firebase Admin private key with escaped newlines |
| `FIREBASE_SERVICE_ACCOUNT_BASE64` | Preferred hosted service-account format |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | Optional local JSON credential path |

Production requires `AUTH_JWT_SECRET` and `CREDENTIAL_ENCRYPTION_KEY` to be at
least 32 characters.

Generate independent random values in PowerShell:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
```

Do not use the JWT secret as the credential encryption key. Keep the
encryption key unchanged across deployments; changing it makes existing
encrypted provider credentials unreadable.

## Firebase Admin credentials

Use one of these methods, in priority order:

1. `FIREBASE_SERVICE_ACCOUNT_BASE64`
2. A local `service-account.json`
3. `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, and `FIREBASE_PRIVATE_KEY`

For Azure, convert the service-account file to one Base64 value:

```powershell
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes(".\service-account.json")
)
```

Store the output in `FIREBASE_SERVICE_ACCOUNT_BASE64`. Never commit
`service-account.json`.

Firestore stores only encrypted provider values under:

```text
users/{hashed-owner-id}/providerCredentials/{provider}
```

The owner ID is a one-way SHA-256-derived identifier. Encryption provides
confidentiality and AES-GCM authentication detects tampering. Hashing alone is
not used for tokens because the application must decrypt them to call provider
APIs.

## Provider setup

### GitHub

GitHub is connected during Firebase GitHub sign-in. The resulting access token
is scoped to the signed-in user, so repository visibility follows that user's
GitHub permissions.

### Vercel

There are two separate connection modes:

- Sign in with Vercel OAuth identifies an account.
- A Vercel personal access token enables project, deployment, and log APIs.

For monitoring, use a token created by a user who belongs to the team that owns
the project. A `403` from Vercel usually means the token can identify the user
but cannot access the requested project/team.

Create a token at `https://vercel.com/account/settings/tokens`.

### Render

Create an API key in **Render Dashboard > Account Settings > API Keys**. The
key owner must have access to the workspace and services being monitored.

## Monitoring flow

1. A user imports a GitHub repository.
2. RecallOps stores its latest commit as the initial baseline.
3. The scheduler checks each repository at its configured polling interval.
4. A new commit creates a commit workflow record.
5. Mapped Vercel and Render resources are inspected through the Python API.
6. Failed deployments are diagnosed and retained as incidents.
7. Generated fixes and draft PR results are linked back to the commit workflow.

The scheduler wakes every two seconds, while each repository's
`poll_interval_seconds` determines whether it is due. `MONITOR_INTERVAL_MS=0`
disables the scheduler.

Very short intervals are useful for demonstrations but may consume provider
API quotas. Use a longer interval in production unless rapid polling is
required.

## API overview

### Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/firebase`
- `GET /api/auth/me`

### Integrations

- `GET /api/integrations/status`
- `GET /api/integrations/github/repositories`
- `POST /api/integrations/repositories/import`
- `GET /api/integrations/repositories/:owner/:repo/activity`
- `PATCH /api/integrations/repositories/:owner/:repo/settings`
- `POST /api/integrations/vercel/token`
- `GET /api/integrations/vercel/projects`
- `POST /api/integrations/render/connect`
- `GET /api/integrations/provider-health`
- `POST /api/integrations/provider-health/track`
- `POST /api/integrations/tracked-projects`
- `DELETE /api/integrations/connections/:provider`
- `GET /api/integrations/runtime`

All integration routes except the OAuth callback require a RecallOps bearer
token.

## Azure App Service deployment

Deploy this folder as the application root.

- Runtime: Node 22 LTS
- Startup command: `npm start`
- Persistent SQLite path: `/home/data/auth.db`
- Enable App Service storage

Import `azure-app-settings.json` through **Configuration > Advanced edit**, but
replace placeholders and secrets before applying it. Restart the App Service
after any environment change.

The production callback registered with Vercel must exactly equal:

```text
https://ima-node-ckgjatf7btgeczgd.canadacentral-01.azurewebsites.net/api/integrations/vercel/callback
```

## Troubleshooting

### `Firebase: Error (auth/operation-not-allowed)`

Enable GitHub in Firebase Authentication.

### Firebase authentication returns HTTP 500

Check Firebase Admin credentials and ensure the production frontend domain is
listed in Firebase Authorized domains.

### Vercel reports an invalid redirect URL

The application callback, `VERCEL_CALLBACK_URL`, and the URL registered with
Vercel must match exactly, including HTTPS and path.

### Vercel returns `invalid_scope`

Use supported identity scopes for OAuth. Use a personal access token for
deployment/project APIs rather than adding unsupported deployment scopes.

### Provider tokens disappear after deployment

Confirm Firestore is reachable, App Service storage is enabled, and the same
`CREDENTIAL_ENCRYPTION_KEY` is present in every deployment slot.

### SQLite and scaling

SQLite is suitable for one App Service instance. Move state to a managed
database before scaling to multiple instances.

## Security

- Never commit `.env`, Firebase private keys, access tokens, or populated Azure
  settings.
- Rotate any credential that has entered Git history.
- Keep `AUTH_JWT_SECRET` identical only between the two trusted backend
  services.
- Keep `CREDENTIAL_ENCRYPTION_KEY` private to the Node service.
- Provider credentials are isolated by authenticated user ID.
