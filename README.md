# ChatWave - WhatsApp Style Chat Website

A full-stack real-time chat app with a clean WhatsApp-inspired UI and email/password authentication.

## Features

- Email-based auth: register + login
- 1:1 chats by searching users with name/email
- Group chat creation with member picker
- Real-time messaging over Socket.IO
- File/image sharing in chat
- Typing indicators
- Online/offline presence
- Read receipts + unread counters
- Edit and delete your own messages
- Reply to a specific message
- Message reactions
- Pin / unpin messages
- Status / stories (24-hour updates)
- Audio + video calling (WebRTC signaling via Socket.IO)
- Chat-level text encryption mode (AES-GCM; passphrase stored locally per user)
- Profile updates (name/about)
- Responsive desktop and mobile layout

## Tech Stack

- Frontend: React + TypeScript + Vite
- Backend: Node.js + Express + Socket.IO
- Storage: JSON persistence in `server/data/db.json`
- Auth: JWT + bcrypt password hashing
- Uploads: multer (`server/uploads`)

## Setup

1. Install dependencies:

```bash
npm install
```

2. Optional: create `.env` from `.env.example` and customize values.

3. Start app (frontend + backend together):

```bash
npm run dev
```

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:3001`

## Scripts

- `npm run dev` - run client and server together
- `npm run dev:client` - run only Vite frontend
- `npm run dev:server` - run only backend with watch mode
- `npm run build` - build frontend app
- `npm run start` - run backend in production mode

## Deploy (Render)

This project is configured for a single-service Render deployment:

1. Push this repo to GitHub.
2. In Render, choose `New +` -> `Blueprint`.
3. Select this repository.
4. Render will detect [`render.yaml`](./render.yaml) and create the service.
5. Deploy.

Or create a Web Service manually:

- Build command: `npm install && npm run build`
- Start command: `npm run start`
- Env vars:
  - `NODE_ENV=production`
  - `JWT_SECRET=<strong-random-secret>`
  - `CLIENT_ORIGIN=*`
  - `DATA_DIR=/path/to/persistent-volume`

## Notes

- Uploaded files are served from `server/uploads`.
- App data is persisted in `server/data/db.json`.
- Change `JWT_SECRET` before production deployment.
- `server/data` and `server/uploads` are file-based. On most cloud platforms, this storage is ephemeral unless you attach a persistent disk or migrate to a database/object storage.
- Set `DATA_DIR` to your mounted persistent disk path (for example `/data`) to keep accounts/messages across redeploys.
