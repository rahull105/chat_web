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

## Notes

- Uploaded files are served from `server/uploads`.
- App data is persisted in `server/data/db.json`.
- Change `JWT_SECRET` before production deployment.
