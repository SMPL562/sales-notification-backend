# Sales Notification Backend

## Project Overview
- **Stack**: Node.js, Express, WebSocket (ws), JWT, SendGrid, dotenv, express-rate-limit, CORS
- **Description**: Backend service powering real-time sales notifications for ~300 BDEs at Coding Ninjas. Receives webhooks from LeadSquared, authenticates users via OTP/JWT, and broadcasts notifications to Chrome extension clients over WebSocket. Deployed on Render.

## File Organization
- Never save working files to root folder
- Single-file server: `server.js` contains all application logic (Express routes, WebSocket server, memory management classes)
- `Procfile` configures Render deployment
- `tokens.json` is generated at runtime for persistent token storage

## Key Architecture
- `LRUCache`, `FileBackedStorage`, `ClientManager`, `MemoryManager` classes handle state
- WebSocket path: `/ws` with JWT token auth via query param
- API endpoints: `/request-otp`, `/verify-otp`, `/webhook`, `/ping`, `/stats`, `/health`
- CORS restricted to `chrome-extension://${EXTENSION_ID}`
- Memory limit: 256MB (`--max-old-space-size=256`)

## Build & Test
```bash
npm install          # Install dependencies
npm start            # Production: node --max-old-space-size=256 server.js
npm run dev          # Development: nodemon --max-old-space-size=256 server.js
```

## Environment Variables
Required (see `.env.example`):
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)
- `EXTENSION_ID` - Chrome Extension ID for CORS/origin validation
- `WEBHOOK_TOKEN` - Bearer token for LeadSquared webhook auth
- `JWT_SECRET` - Secret for signing JWT tokens
- `SENDGRID_API_KEY` - SendGrid API key for OTP emails

## Security Rules
- NEVER hardcode API keys, secrets, or credentials in any file
- NEVER pass credentials as inline env vars in Bash commands
- NEVER commit .env, .claude/settings.local.json, or .mcp.json to git
