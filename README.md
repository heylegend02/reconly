# OSINT Command Center (Web)

Web-based OSINT platform with:

- Red Team recon modules (enumeration, identity, email, infra mapping, leak detection, metadata extraction, recon pipeline)
- Blue Team defense modules (attack surface monitoring, threat intel, brand monitoring, credential leaks, log enrichment, alerting, vulnerability intelligence)
- Authentication (register/login), role-based access (`admin`, `red`, `blue`)
- Team-based access control (red accounts -> red modules only, blue accounts -> blue modules only)
- Admin-only user management, activity logs, and alert visibility

## Stack

- Node.js + Express + EJS
- SQLite via `sql.js` file persistence (users, activity logs, monitored assets, alerts)
- `express-session` for authenticated sessions

## Quick start

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create env file:
   ```bash
   copy .env.example .env
   ```
3. Start app:
   ```bash
   npm start
   ```
4. Open:
   `http://localhost:3000`

## Render deployment

- A ready-to-use [`render.yaml`](./render.yaml) is included for Blueprint deployment.
- The app stores SQLite data on disk, so Render needs a persistent disk mounted at `/var/data`.
- Because persistent disks require a paid web service, the Blueprint uses the `starter` plan.
- Set `ADMIN_PASSWORD` in the Render dashboard before the first production deploy.
- Render will use the Node version pinned in [`.node-version`](./.node-version).

## Team selection at registration

During registration, users must choose:

- `Red Team` account (access only Red Team functionalities)
- `Blue Team` account (access only Blue Team functionalities)

`Admin` accounts can access both Red and Blue modules.

## Default admin

The app auto-seeds one admin account on first start using `.env` values:

- `ADMIN_USERNAME` (default: `admin`)
- `ADMIN_EMAIL` (default: `admin@osint.local`)
- `ADMIN_PASSWORD` (default: `admin@123`)

Change these defaults before exposing the app.

## Admin controls

Admin can access:

- `/admin/users`: view user details, password hashes, per-user activity, edit username/email/role/password, delete users
- `/admin/logs`: system-wide activity audit logs

## Optional API keys

Add API keys in `.env` for enhanced modules:

- `HIBP_API_KEY` (credential/email breach checks)
- `GITHUB_TOKEN` (code leak search)
- `VIRUSTOTAL_API_KEY` (IOC/domain reputation)
- `ABUSEIPDB_API_KEY` (IP abuse scoring)

Without keys, the tool still runs and returns graceful "not configured" responses for those integrations.
