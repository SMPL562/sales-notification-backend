# Sales Notification Backend - Environment Reference

## Local Development

### Prerequisites

- Node.js 16+ (20 recommended)
- npm
- A SendGrid account with API key
- A Chrome extension ID (for CORS origin)

### Setup

```bash
# Clone
git clone https://github.com/SMPL562/sales-notification-backend.git
cd sales-notification-backend

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env: fill in all four required variables
```

### Run

```bash
# Development (nodemon, auto-reload)
npm run dev

# Production
npm start
```

Both modes run with `--max-old-space-size=256` (256MB memory limit).

### Access

| Endpoint   | URL                          |
|------------|------------------------------|
| HTTP API   | http://localhost:3000         |
| WebSocket  | ws://localhost:3000/ws        |
| Health     | http://localhost:3000/health  |
| Stats      | http://localhost:3000/stats   |
| Ping       | http://localhost:3000/ping    |

### Testing the webhook locally

```bash
curl -X POST http://localhost:3000/webhook \
  -H "Authorization: Bearer YOUR_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"notification","message":"Test notification"}'
```

## Production / Deployment

### Render (current)

Deployed on Render at `https://sales-notification-backend.onrender.com`.

- **Procfile**: `web: node server.js`
- Environment variables are set in the Render dashboard (Environment tab)
- Render auto-deploys on push to the connected branch
- The `/ping` endpoint keeps the service awake (free tier spins down on inactivity)

### Deploying to Render

1. Create a new Web Service on Render, connect the GitHub repo
2. Set the four required environment variables in the Render Environment tab
3. Render detects the `Procfile` and deploys automatically

### LeadSquared webhook config

Point your LeadSquared webhook to:
- **URL**: `https://sales-notification-backend.onrender.com/webhook`
- **Method**: POST
- **Headers**: `Authorization: Bearer <WEBHOOK_TOKEN>`, `Content-Type: application/json`

## Environment Variables

| Variable          | Required | Default       | Description                                       |
|-------------------|----------|---------------|---------------------------------------------------|
| `PORT`            | No       | `3000`        | Server port                                       |
| `NODE_ENV`        | No       | `development` | Environment (development/production)              |
| `EXTENSION_ID`    | Yes      | --            | Chrome Extension ID for CORS origin validation    |
| `WEBHOOK_TOKEN`   | Yes      | --            | Bearer token for LeadSquared webhook auth         |
| `JWT_SECRET`      | Yes      | --            | Secret for signing JWT tokens (OTP auth)          |
| `SENDGRID_API_KEY`| Yes      | --            | SendGrid API key for sending OTP emails           |

Source: `.env.example`

**All four required variables must be set or the server exits on startup.**

## CI/CD

**Pipeline**: `.github/workflows/ci.yml`
**Runs on**: `ubuntu-latest`
**Triggers**: Push to `main`/`master`, pull requests to `main`/`master`

### Jobs

1. **Syntax check** -- `node --check` on all `.js` files
2. **Security audit (npm)** -- Critical-level audit, advisory
3. **Env validation** -- Checks `.env.example` exists and lists required vars

### Status

GREEN -- runs on GitHub-hosted runners. No Docker build in CI (not containerized).

## Architecture Notes

- **Single-file server**: All logic is in `server.js` (Express routes, WebSocket server, memory management)
- **In-memory state**: OTPs, tokens, and client connections are stored in memory. Lost on restart.
- **`tokens.json`**: Generated at runtime by `FileBackedStorage` for persistent token storage. Saved every 60s.
- **Memory limit**: 256MB (`--max-old-space-size=256`), with automatic cleanup at 200MB
- **Rate limits**: 100 requests per IP per 15 minutes on OTP endpoints
- **WebSocket limits**: 1 connection per token, 5-second minimum between reconnects

## Troubleshooting

### Server exits immediately on startup

All four required env vars (`EXTENSION_ID`, `WEBHOOK_TOKEN`, `JWT_SECRET`, `SENDGRID_API_KEY`) must be set. The server validates on startup and `process.exit(1)` if any are missing.

### WebSocket connection rejected

Common causes:
- **Invalid origin**: The client must connect from `chrome-extension://<EXTENSION_ID>`. Browser-based WebSocket tools will fail.
- **Missing/expired token**: The `?token=` query param must be a valid JWT from `/verify-otp`.
- **Too frequent connections**: Minimum 5-second gap between connections per token.

### OTPs not arriving

- Verify `SENDGRID_API_KEY` is valid and the sender domain (`noreply@codingninjas.com`) is verified in SendGrid.
- OTPs expire after 5 minutes.
- OTPs are stored in memory -- server restart clears them.

### High memory warnings in logs

The `MemoryManager` logs a warning at 200MB heap usage and triggers cleanup. If this happens frequently, check for WebSocket connection leaks (clients not disconnecting properly).

### Render free tier spin-down

The `/ping` endpoint returns `{"status":"alive"}`. Use an external cron/uptime monitor to hit it every ~5 minutes to keep the service awake.
