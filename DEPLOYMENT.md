# Deployment (new repo -> Cloudflare Pages)

This repo now includes an automatic deployment workflow:

- Workflow: `.github/workflows/deploy-cloudflare-pages.yml`
- Trigger: push to `main` when files under `Website/` change
- Deploy command: `wrangler pages deploy Website --project-name=<project>`

## Required GitHub secrets

Configure these repository secrets in `jnjolstad/SecurityAwarenessMonth`:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_PAGES_PROJECT`

The workflow now validates these up-front and fails with explicit errors if any are missing.

## Admin security configuration (required for admin panel)

All auth/runtime variables are now centralized in:

- `Website/functions/_config.js`

This is the single config module used by both:
- `Website/functions/_auth.js`
- `Website/functions/security-awareness-month/minigames-api/[[path]].js`

Configure Pages Function environment variables:

- `SAM_MINIGAMES_ADMIN_EMAILS` (comma-separated allowed admin emails)
- `SAM_MINIGAMES_SESSION_SECRET` (strong random secret for signing admin session cookies)
- `RESEND_API_KEY` (Resend API key used to send one-time admin login links)
- `SAM_MINIGAMES_EMAIL_FROM` (verified sender, e.g. `Security Awareness <security@njolstad.no>`)
- `SAM_MINIGAMES_ADMIN_LOGIN_TTL_MS` (optional; magic-link validity in ms, clamped to 1–60 minutes; default 900000)

The admin page (`/admin`) now uses **email-only magic-link login**:

1. Admin enters email.
2. API sends one-time link by email (15 minute expiry, single-use).
3. Link verification creates an HttpOnly signed session cookie.

Global admins come from `SAM_MINIGAMES_ADMIN_EMAILS`; group admins added in the UI can also log in by email-only and are scoped to their group permissions.
When a global admin adds a group admin, the API now sends that group admin the same one-time login email automatically.

For troubleshooting, use:

- `GET /security-awareness-month/minigames-api/auth/debug`

This endpoint is safe to share in logs because it returns only booleans/flags (never secret values), including whether required env vars are missing or too short.

## Quick setup path (Cloudflare + GitHub)

1. Cloudflare Pages -> your project -> **Settings -> Builds & deployments -> Source**.
2. Connect source to `jnjolstad/SecurityAwarenessMonth` (`main`).
3. In Cloudflare Pages project settings, set:
   - **Framework preset**: None
   - **Build command**: *(empty)*
   - **Root directory**: `Website` (the name is case-sensitive, and `functions/` must be inside the root directory for the API to deploy)
   - **Build output directory**: *(empty)*
4. Trigger a new deployment in Cloudflare Pages for `main`.
5. (Optional) In GitHub repo settings, add the 3 secrets listed above if you want API-driven deploy from GitHub Actions too.
6. Add custom domain for this project:
   - `securityawarenessmonth.njolstad.no`
7. Verify the live admin script contains `admin-panel-v3`:
   - `https://securityawarenessmonth.njolstad.no/admin/admin.js`

If you want to keep `www.njolstad.no` for other content, do not attach `www` to this Pages project.

## Cloudflare Pages bindings and variables

Set these under the Pages project's **Settings -> Bindings** and **Variables and Secrets** (Production, and Preview if used). They are applied on the next deployment.

- D1 binding `AUKSJON_DB` (the leaderboard tables are prefixed `sam_mg_` and are created automatically)
- `SAM_MINIGAMES_ADMIN_EMAILS` (comma-separated global admins)
- `SAM_MINIGAMES_ADMIN_KEY` (secret, at least 24 characters)
- `SAM_MINIGAMES_SESSION_SECRET` (secret, different from the admin key)
- `RESEND_API_KEY` (secret) and `SAM_MINIGAMES_EMAIL_FROM` (a sender verified in Resend), used for admin login links

The admin page has a **Diagnostics** section that shows which of these are missing.

## Notes

- The published site must use this repository/workflow to serve new code.
- If the live page still shows old JavaScript after a successful run, do a hard refresh (`Ctrl+F5`) or append a cache-buster query.
- To verify the admin-panel build is live, check that the served `/admin/admin.js` contains `admin-panel-v3`.
