# Tiny E2E Chat (minimal demo)

A minimal, runnable private end-to-end encrypted realtime chat (rooms + typing + presence).
Server: Node.js + Express + Socket.IO.
Client: Single `index.html` using Web Crypto (ECDH P-256 + AES-GCM).

> Port: `process.env.PORT || 8080` (default 8080)

## Files
- `server.js` — Express + Socket.IO backend (stores ciphertext only)
- `seed.js` — optional demo seed (creates a room and an owner's private key file for demo import)
- `public/` — frontend: `index.html`, `main.js`, `styles.css`
- `data/rooms.json` — persisted room metadata & message ciphertexts
- `.env.example` — example env

## Quick run (Windows / VS Code)
1. Install Node.js (v18+ recommended).
2. Open project in VS Code (or a terminal in project folder).
3. Run:
   ```powershell
   npm install
   npm run seed     # OPTIONAL: creates a demo room + writes owner key to data/seed_admin_key.json
   npm run start
