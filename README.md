# SENTINEL Web Observatory

SENTINEL performs passive website investigations using the URL submitted by the user. It collects available DNS, HTTP, redirect, TLS, and page-content evidence, then reports module status and risk assessment. Private and reserved IP ranges are blocked, and redirects are validated before they are followed.

## Requirements

- Node.js 22.12 or newer
- npm

## Local development

```powershell
npm ci
Copy-Item .env.example .env
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

`GEMINI_API_KEY` is optional. When configured, set it only in the local, ignored `.env` file or your deployment platform's secret manager. The key is read by the server and is not required by the browser. Never add real credentials to `.env.example`, source files, screenshots, issue reports, or commits.

## Tests and production build

```powershell
npm test
npm run lint
npm run build
npm start
```

The production build creates the static frontend in `dist/` and a bundled Node server entry point in `server.js`. Test-only routes and fixture data are excluded from the server bundle. Run `npm start` after building. Set `NODE_ENV=production` in the deployment environment. Do not deploy `.env` with the build.

Vercel deployments use [vercel.json](./vercel.json) to serve the frontend from `dist/` and route `/api/*` requests through the Node API function in `api/[...path].ts`. Configure `GEMINI_API_KEY` and any trusted-proxy settings in the Vercel project environment, then redeploy after changing them.

## Data and external services

- Live scan results are returned to the requester but are not retained or listed when `NODE_ENV=production`. In development and tests, history is in-memory and is lost when the process restarts.
- Community report listing is empty and report submission/verification are disabled in production until authenticated moderation and a retention policy are implemented. In development and tests, reports are in-memory.
- API requests are rate-limited per client IP in the running process. Use a distributed rate-limit store before deploying multiple server instances. If behind a reverse proxy, set `TRUST_PROXY` only to its known network name/IP/CIDR; boolean trust-all and hop-count settings are rejected.
- No external threat-intelligence feeds are configured by default. Production community matching has no reports until a protected intelligence source is configured.
- Gemini analysis is optional. When its key is not configured or the service is unavailable, the AI module reports unavailable rather than fabricating an assessment.
- The controlled tests use test fixtures and a local HTTP server; test fixtures are not returned by the production scan endpoint.

## Publishing safely

Before pushing to a public repository:

1. Keep real API keys, `.env` files, local reports, databases, logs, certificates, and generated output out of Git. `.gitignore` excludes these paths; `.env.example` contains placeholders only.
2. Review staged files (`git status --short`) before every push. Ignore rules do not remove files already tracked or erase secrets from Git history.
3. If a credential was ever committed or shared, revoke/rotate it immediately. Deleting it from the latest commit is not sufficient.
4. Configure production credentials in your hosting provider's secret manager, not in GitHub source, frontend variables, or browser code.
5. Enable GitHub secret scanning and push protection where available.

This repository does not include real user scan data or a production database. The test suite includes controlled fixtures in source code.
