// server.js
// Chat server with server-assisted room key wrapping.
// Fix: removed inline `await` inside object literals by pre-resolving server public JWK or reading it synchronously.
// Requirements: Node 18+ (webcrypto.subtle).

const express = require('express');
const http = require('http');
const fs = require('fs').promises;
const fssync = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');
const { Server } = require('socket.io');
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_PATH = path.join(DATA_DIR, 'rooms.json');
const BAN_PATH = path.join(DATA_DIR, 'banned.json');
const SERVER_KEY_PATH = path.join(DATA_DIR, 'server_key.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'dev-secret';

const BUILD_ID = Date.now();
console.log('BUILD_ID', BUILD_ID);

// Load or generate SERVER_MASTER_KEY (base64 -> 32 bytes)
const SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY || null;
let SERVER_MASTER_KEY = null;
if (SERVER_MASTER_KEY_B64) {
  try {
    const buf = Buffer.from(SERVER_MASTER_KEY_B64, 'base64');
    if (buf.length === 32) SERVER_MASTER_KEY = buf;
    else console.warn('SERVER_MASTER_KEY is present but not 32 bytes; falling back to ephemeral key');
  } catch (e) {
    console.warn('Invalid SERVER_MASTER_KEY, using ephemeral key');
  }
}
if (!SERVER_MASTER_KEY) {
  console.warn('No valid SERVER_MASTER_KEY found; generating ephemeral key (not persisted across restarts)');
  SERVER_MASTER_KEY = require('crypto').randomBytes(32);
}

// In-memory runtime state
const sessions = new Map();
const roomTypers = new Map();
const adminSessions = new Map();

// In-memory data cache + write serialization
let dataCache = { rooms: [] };
let writeMutex = false;
let writePending = false;

function bufToB64(buf) { return Buffer.from(buf).toString('base64'); }
function b64ToBuf(b64) { return Buffer.from(b64, 'base64'); }
function bufferToArrayBuffer(buf) { return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength); }
function arrayBufferToBuffer(ab) { return Buffer.from(new Uint8Array(ab)); }

async function _atomicWrite(filepath, contentStr) {
  const tmp = filepath + '.tmp';
  await fs.mkdir(path.dirname(filepath), { recursive: true });
  await fs.writeFile(tmp, contentStr, 'utf8');
  await fs.rename(tmp, filepath);
}

async function safeReadJSON(filepath, fallback = null) {
  try {
    const raw = await fs.readFile(filepath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === 'ENOENT') return fallback;
    console.error('safeReadJSON error', e);
    throw e;
  }
}

function scheduleWriteData() {
  writePending = true;
  if (!writeMutex) flushWrites().catch(e => console.error('flushWrites', e));
}

async function flushWrites() {
  if (writeMutex) return;
  writeMutex = true;
  try {
    while (writePending) {
      writePending = false;
      const snapshot = JSON.stringify(dataCache, null, 2);
      try {
        await _atomicWrite(DATA_PATH, snapshot);
      } catch (e) {
        console.error('write error', e);
        writePending = true;
        await new Promise(r => setTimeout(r, 200));
      }
    }
  } finally {
    writeMutex = false;
  }
}

async function loadInitialData() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  dataCache = (await safeReadJSON(DATA_PATH, { rooms: [] })) || { rooms: [] };
}
loadInitialData().catch(e => { console.error('Failed to load initial data', e); process.exit(1); });

// banlist helpers
async function readBanList() { return await safeReadJSON(BAN_PATH, []); }
async function writeBanList(list) { await _atomicWrite(BAN_PATH, JSON.stringify(list, null, 2)); }

// find helpers
function findRoomById(id) { return dataCache.rooms.find(r => r.id === id) || null; }
function findRoomByToken(token) { if (!token) return null; return dataCache.rooms.find(r => r.inviteToken === token) || null; }

// server keypair helpers
// ensureServerKeypair remains async because key generation uses subtle.generateKey
async function ensureServerKeypair() {
  try {
    if (fssync.existsSync(SERVER_KEY_PATH)) {
      const json = await safeReadJSON(SERVER_KEY_PATH, null);
      if (json && json.publicJwk && json.privateJwk) return json;
    }
  } catch (e) {
    console.warn('reading existing server key failed, regenerating', e);
  }
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey','deriveBits']);
  const pub = await subtle.exportKey('jwk', kp.publicKey);
  const priv = await subtle.exportKey('jwk', kp.privateKey);
  const out = { publicJwk: pub, privateJwk: priv };
  await _atomicWrite(SERVER_KEY_PATH, JSON.stringify(out, null, 2));
  console.log('Generated and saved server ECDH keypair to', SERVER_KEY_PATH);
  return out;
}

// synchronous helper to get server public JWK when we only need the publicJwk in a synchronous expression.
// This avoids writing `(await ensureServerKeypair()).publicJwk` inside object literals.
function getServerPublicJwkSync() {
  try {
    if (!fssync.existsSync(SERVER_KEY_PATH)) return null;
    const raw = fssync.readFileSync(SERVER_KEY_PATH, 'utf8');
    const json = JSON.parse(raw);
    if (json && json.publicJwk) return json.publicJwk;
  } catch (e) {
    // ignore; caller can fallback to awaiting ensureServerKeypair()
  }
  return null;
}

let cachedServerPrivateKeyCrypto = null;
async function getServerPrivateCryptoKey() {
  if (cachedServerPrivateKeyCrypto) return cachedServerPrivateKeyCrypto;
  const pair = await ensureServerKeypair();
  cachedServerPrivateKeyCrypto = await subtle.importKey('jwk', pair.privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey','deriveBits']);
  return cachedServerPrivateKeyCrypto;
}

// Master AES key import for at-rest encryption
async function importMasterKeyForAes() {
  return subtle.importKey('raw', bufferToArrayBuffer(SERVER_MASTER_KEY), { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
}
async function encryptRoomKeyAtRest(rawRoomKeyBuf) {
  const master = await importMasterKeyForAes();
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, master, bufferToArrayBuffer(rawRoomKeyBuf));
  return { ciphertext: bufToB64(arrayBufferToBuffer(ct)), iv: bufToB64(iv) };
}
async function decryptRoomKeyAtRest(encObj) {
  if (!encObj || !encObj.ciphertext || !encObj.iv) return null;
  const master = await importMasterKeyForAes();
  const ct = b64ToBuf(encObj.ciphertext);
  const iv = b64ToBuf(encObj.iv);
  const plainAb = await subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, master, bufferToArrayBuffer(ct));
  return arrayBufferToBuffer(plainAb); // Buffer
}

// wrap room key for client using ECDH(serverPriv + clientPub) -> derived AES-GCM -> encrypt raw room key
async function wrapRoomKeyForClient(clientPublicJwk, rawRoomKeyBuf) {
  const clientPub = await subtle.importKey('jwk', clientPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const serverPriv = await getServerPrivateCryptoKey();
  const derivedBits = await subtle.deriveBits({ name: 'ECDH', public: clientPub }, serverPriv, 256);
  const derivedKey = await subtle.importKey('raw', derivedBits, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const wrappedAb = await subtle.encrypt({ name: 'AES-GCM', iv }, derivedKey, bufferToArrayBuffer(rawRoomKeyBuf));
  return { wrappedKey: bufToB64(arrayBufferToBuffer(wrappedAb)), iv: bufToB64(iv) };
}

// raw room symmetric key generator (32 bytes)
function generateRoomSymKeyBuf() { return require('crypto').randomBytes(32); }

// presence gather
async function gatherPresence(roomId) {
  const room = findRoomById(roomId);
  if (!room) return { members: [] };
  const members = Object.keys(room.membersPublic || {});
  const result = members.map(username => {
    let online = false;
    let lastSeen = null;
    for (const [sid, s] of sessions) {
      if (s.username === username && s.roomId === roomId) {
        online = true;
        lastSeen = s.lastSeen || Date.now();
        break;
      }
    }
    return { username, online, lastSeen: online ? null : lastSeen };
  });
  return { members: result };
}

// express + socket.io setup
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET','POST'] } });

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});
app.use(express.static(PUBLIC_DIR, { index: false, etag: false, lastModified: false }));
app.use(bodyParser.json({ limit: '10mb' }));

app.get(['/', '/index.html'], async (req, res) => {
  try {
    const htmlPath = path.join(PUBLIC_DIR, 'index.html');
    let html = await fs.readFile(htmlPath, 'utf8');
    const bootstrap = `\n<script>(function(){ try { const SERVER_BUILD = ${BUILD_ID}; const KEY = 'APP_BUILD_ID'; const prev = localStorage.getItem(KEY); if (prev && Number(prev) !== SERVER_BUILD) { if ('serviceWorker' in navigator) navigator.serviceWorker.getRegistrations().then(regs=>regs.forEach(r=>r.unregister())).catch(()=>{}); if (window.caches && caches.keys) caches.keys().then(keys=>Promise.all(keys.map(k=>caches.delete(k)))).catch(()=>{}); localStorage.setItem(KEY, String(SERVER_BUILD)); if (!sessionStorage.getItem('reloaded_for_build')) { sessionStorage.setItem('reloaded_for_build','1'); window.location.reload(true); } else { sessionStorage.removeItem('reloaded_for_build'); } } else { localStorage.setItem(KEY, String(SERVER_BUILD)); } } catch(e) { console.warn('bootstrap', e); } })();</script>\n`;
    const socketUrl = `/socket.io/socket.io.js?b=${BUILD_ID}`;
    const mainUrl = `/mainv6.js?b=${BUILD_ID}`;
    const inject = `${bootstrap}\n<link rel="stylesheet" href="/styles.css?b=${BUILD_ID}">\n<script src="${socketUrl}"></script>\n<script src="${mainUrl}" defer></script>\n`;
    html = html.includes('<!-- INJECT_SCRIPTS -->') ? html.replace('<!-- INJECT_SCRIPTS -->', inject) : html.replace('</body>', `${inject}</body>`);
    res.type('html').send(html);
  } catch (e) {
    console.error('serve index error', e);
    res.status(500).send('index read error');
  }
});

app.get('/mainv6.js', async (req, res) => {
  try {
    const jsPath = path.join(PUBLIC_DIR, 'mainv6.js');
    const content = await fs.readFile(jsPath, 'utf8');
    res.set('Content-Type', 'application/javascript; charset=utf-8');
    res.send(content);
  } catch (e) {
    console.error('serve mainv6.js error', e);
    res.status(500).send('// mainv6.js not found');
  }
});

app.get('/admin.html', async (req, res) => {
  try {
    const p = path.join(PUBLIC_DIR, 'admin.html');
    let html = await fs.readFile(p, 'utf8');
    const inject = `<script src="/admin.js?b=${BUILD_ID}" defer></script><link rel="stylesheet" href="/styles.css?b=${BUILD_ID}">`;
    html = html.replace('<!-- INJECT_SCRIPTS -->', inject);
    res.type('html').send(html);
  } catch (e) {
    console.error('serve admin.html error', e);
    res.status(500).send('admin not found');
  }
});

// API endpoints
app.get('/_version', (req, res) => res.json({ build: BUILD_ID, started: new Date().toISOString(), pid: process.pid }));

app.get('/api/rooms', async (req, res) => {
  try {
    const rooms = (dataCache.rooms || []).map(r => ({
      id: r.id, name: r.name, isPrivate: !!r.isPrivate, owner: r.owner, hasInvite: !!r.inviteToken
    }));
    res.json({ rooms });
  } catch (e) {
    console.error('/api/rooms error', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/rooms', async (req, res) => {
  try {
    const { name, isPrivate, owner, ownerPublicJwk, inviteToken } = req.body || {};
    if (!name || !owner || !ownerPublicJwk) return res.status(400).json({ error: 'name, owner, ownerPublicJwk required' });

    const id = uuidv4();
    let token = null;
    if (isPrivate) {
      if (inviteToken && typeof inviteToken === 'string' && inviteToken.trim().length >= 4 && inviteToken.trim().length <= 64) token = inviteToken.trim();
      else token = Math.random().toString(36).slice(2, 10);
    }

    const rawRoomKey = generateRoomSymKeyBuf();
    const encRoomKey = await encryptRoomKeyAtRest(rawRoomKey);

    // Try to obtain server public JWK synchronously first; if missing, await ensureServerKeypair
    let serverPub = getServerPublicJwkSync();
    if (!serverPub) {
      const pair = await ensureServerKeypair();
      serverPub = pair.publicJwk;
    }

    const room = {
      id, name, isPrivate: !!isPrivate, owner, inviteToken: token || null,
      serverPublicJwk: serverPub,
      encRoomKey,
      banned: [],
      membersPublic: { [owner]: ownerPublicJwk },
      history: []
    };

    dataCache.rooms.push(room);
    scheduleWriteData();

    return res.json({ roomId: id, inviteToken: token || null });
  } catch (e) {
    console.error('POST /api/rooms error', e);
    res.status(500).json({ error: 'server error' });
  }
});

// admin endpoints
function verifyAdminToken(req) {
  const token = req.get('x-admin-token') || '';
  return token && adminSessions.has(token);
}

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    if (username !== ADMIN_USER || password !== ADMIN_PASS) return res.status(403).json({ error: 'unauthorized' });
    const token = uuidv4();
    adminSessions.set(token, { createdAt: Date.now() });
    return res.json({ adminToken: token });
  } catch (e) { console.error('admin login error', e); res.status(500).json({ error: 'server error' }); }
});

app.post('/api/admin/logout', (req, res) => {
  try {
    const token = req.get('x-admin-token') || '';
    if (token && adminSessions.has(token)) adminSessions.delete(token);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server error' }); }
});

app.post('/api/admin/sync-chats', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const { rooms } = req.body || {};
    if (!Array.isArray(rooms)) return res.status(400).json({ error: 'rooms array required' });

    // Get server public JWK synchronously if possible; otherwise await keypair first.
    let serverPub = getServerPublicJwkSync();
    if (!serverPub) {
      const pair = await ensureServerKeypair();
      serverPub = pair.publicJwk;
    }

    const normalized = rooms.map(r => ({
      id: r.id || uuidv4(),
      name: r.name || 'room',
      isPrivate: !!r.isPrivate,
      owner: r.owner || 'owner',
      inviteToken: r.inviteToken || null,
      serverPublicJwk: r.serverPublicJwk || serverPub,
      encRoomKey: r.encRoomKey || null,
      banned: r.banned || [],
      membersPublic: r.membersPublic || {},
      history: r.history || []
    }));

    dataCache.rooms = normalized;
    scheduleWriteData();
    return res.json({ ok: true, count: dataCache.rooms.length });
  } catch (e) {
    console.error('admin sync error', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/admin/delete-room', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const { roomId } = req.body || {};
    if (!roomId) return res.status(400).json({ error: 'roomId required' });
    const idx = dataCache.rooms.findIndex(r => r.id === roomId);
    if (idx === -1) return res.status(404).json({ error: 'room not found' });
    dataCache.rooms.splice(idx, 1);
    scheduleWriteData();
    io.to(roomId).emit('system:notice', { text: 'This room has been deleted by an admin.' });
    return res.json({ ok: true });
  } catch (e) { console.error('admin delete-room error', e); res.status(500).json({ error: 'server error' }); }
});

app.post('/api/admin/upload-banlist', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const { banned } = req.body || {};
    if (!Array.isArray(banned)) return res.status(400).json({ error: 'banned array required' });
    await writeBanList(banned);
    return res.json({ ok: true, count: banned.length });
  } catch (e) { console.error('upload banlist error', e); res.status(500).json({ error: 'server error' }); }
});

app.get('/api/admin/banlist', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const list = await readBanList();
    res.json({ banned: list });
  } catch (e) { console.error('get banlist error', e); res.status(500).json({ error: 'server error' }); }
});

app.get('/api/admin/rooms', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    res.json({ rooms: dataCache.rooms || [] });
  } catch (e) { console.error('admin rooms error', e); res.status(500).json({ error: 'server error' }); }
});

// Socket.IO
io.on('connection', (socket) => {
  console.log('socket connected', socket.id);

  function isAdminPayload(payload) {
    if (!payload) return false;
    if (payload.adminSecret && payload.adminSecret === ADMIN_SECRET) return true;
    if (payload.adminToken && adminSessions.has(payload.adminToken)) return true;
    return false;
  }

  function canSendMessage(socketState) {
    const now = Date.now();
    const windowMs = 5000;
    const maxMessages = 10;
    socketState.sendTimestamps = socketState.sendTimestamps || [];
    socketState.sendTimestamps = socketState.sendTimestamps.filter(t => (now - t) <= windowMs);
    if (socketState.sendTimestamps.length >= maxMessages) return false;
    socketState.sendTimestamps.push(now);
    return true;
  }

  socket.on('join', async (payload, ack) => {
    try {
      const { roomIdOrToken, username, publicJwk } = payload || {};
      if (!roomIdOrToken || !username || !publicJwk) {
        if (ack) ack({ ok: false, error: 'roomIdOrToken, username, publicJwk required' });
        return;
      }

      const bannedList = await readBanList();
      if (Array.isArray(bannedList) && bannedList.includes(username)) { if (ack) ack({ ok: false, error: 'you are banned' }); return; }

      let room = findRoomById(roomIdOrToken);
      let usedToken = false;
      if (!room) { room = findRoomByToken(roomIdOrToken); usedToken = !!room; }
      if (!room) { if (ack) ack({ ok: false, error: 'room not found' }); return; }

      if (room.isPrivate) {
        const isOwner = username === room.owner;
        if (!usedToken && !isOwner && !(payload && payload._adminBypass === true)) { if (ack) ack({ ok: false, error: 'room is private; provide invite token' }); return; }
      }

      if ((room.banned || []).includes(username)) { if (ack) ack({ ok: false, error: 'you are banned from this room' }); return; }

      // register session early
      sessions.set(socket.id, { username, roomId: room.id, lastSeen: Date.now(), isAdmin: false, sendTimestamps: [] });

      // persist latest device publicJwk
      room.membersPublic = room.membersPublic || {};
      room.membersPublic[username] = publicJwk;
      scheduleWriteData();

      // prepare wrapped key
      let wrapped = null;
      try {
        const roomSymKeyBuf = await decryptRoomKeyAtRest(room.encRoomKey);
        if (roomSymKeyBuf) wrapped = await wrapRoomKeyForClient(publicJwk, roomSymKeyBuf);
      } catch (e) {
        console.error('wrapRoomKeyForClient failed', e);
      }

      socket.join(room.id);
      const presence = await gatherPresence(room.id);
      io.to(room.id).emit('presence:update', presence);
      io.to(room.id).emit('system:notice', { text: `${username} joined.` });
      io.to(room.id).emit('room:meta', { id: room.id, name: room.name, isPrivate: !!room.isPrivate, inviteToken: room.inviteToken || null, owner: room.owner });

      // Provide a serverPublicJwk for clients: prefer synchronous read, else await keypair.
      let serverPub = getServerPublicJwkSync();
      if (!serverPub) {
        const sp = await ensureServerKeypair();
        serverPub = sp.publicJwk;
      }

      if (ack) ack({
        ok: true,
        data: {
          room: {
            id: room.id, name: room.name, owner: room.owner, isPrivate: !!room.isPrivate, inviteToken: room.inviteToken || null,
            serverPublicJwk: serverPub,
            wrappedRoomKey: wrapped ? wrapped.wrappedKey : null,
            wrappedRoomKeyIv: wrapped ? wrapped.iv : null
          },
          history: room.history || []
        }
      });
    } catch (err) {
      console.error('join error', err);
      if (ack) ack({ ok: false, error: 'server error' });
    }
  });

  socket.on('admin:impersonate', async (payload, ack) => {
    try {
      if (!isAdminPayload(payload)) return ack && ack({ ok: false, error: 'unauthorized' });
      const { roomIdOrToken, username, publicJwk } = payload || {};
      if (!roomIdOrToken || !username || !publicJwk) return ack && ack({ ok: false, error: 'roomIdOrToken, username, publicJwk required' });

      let room = findRoomById(roomIdOrToken) || findRoomByToken(roomIdOrToken);
      if (!room) return ack && ack({ ok: false, error: 'room not found' });

      sessions.set(socket.id, { username, roomId: room.id, lastSeen: Date.now(), isAdmin: true, sendTimestamps: [] });

      room.membersPublic = room.membersPublic || {};
      room.membersPublic[username] = publicJwk;
      scheduleWriteData();

      let wrapped = null;
      try {
        const roomSymKeyBuf = await decryptRoomKeyAtRest(room.encRoomKey);
        if (roomSymKeyBuf) wrapped = await wrapRoomKeyForClient(publicJwk, roomSymKeyBuf);
      } catch (e) { console.error('wrap admin impersonate failed', e); }

      socket.join(room.id);
      const presence = await gatherPresence(room.id);
      io.to(room.id).emit('presence:update', presence);
      io.to(room.id).emit('system:notice', { text: `${username} (admin) joined.` });
      io.to(room.id).emit('room:meta', { id: room.id, name: room.name, isPrivate: !!room.isPrivate, inviteToken: room.inviteToken || null, owner: room.owner });

      // Provide serverPublicJwk (sync preferred)
      let serverPub = getServerPublicJwkSync();
      if (!serverPub) {
        const sp = await ensureServerKeypair();
        serverPub = sp.publicJwk;
      }

      if (ack) ack({ ok: true, data: { room: { id: room.id, name: room.name, owner: room.owner, isPrivate: !!room.isPrivate, inviteToken: room.inviteToken || null, serverPublicJwk: serverPub, wrappedRoomKey: wrapped ? wrapped.wrappedKey : null, wrappedRoomKeyIv: wrapped ? wrapped.iv : null }, history: room.history || [] } });
    } catch (err) {
      console.error('admin impersonate err', err);
      if (ack) ack({ ok: false, error: 'server error' });
    }
  });

  socket.on('message:send', async (payload, ack) => {
    try {
      const session = sessions.get(socket.id);
      if (!session) { if (ack) ack({ ok: false, error: 'not in room' }); return; }

      if (!canSendMessage(session)) { if (ack) ack({ ok: false, error: 'rate limit' }); return; }

      const { roomId, from, ciphertext, iv, ts } = payload || {};
      if (!roomId || !from || !ciphertext || !iv || !ts) { if (ack) ack({ ok: false, error: 'bad payload' }); return; }

      if (session.roomId !== roomId || session.username !== from) { if (ack) ack({ ok: false, error: 'not authorized to send as this user' }); return; }

      const room = findRoomById(roomId);
      if (!room) { if (ack) ack({ ok: false, error: 'room not found' }); return; }

      const message = { id: uuidv4(), from, ciphertext, iv, ts: Number(ts) || Date.now() };
      room.history = room.history || [];
      room.history.push(message);

      scheduleWriteData();
      io.to(roomId).emit('message:new', message);
      if (ack) ack({ ok: true, id: message.id });
    } catch (err) {
      console.error('message:send error', err);
      if (ack) ack({ ok: false, error: 'server error' });
    }
  });

  socket.on('typing:start', (payload) => {
    try {
      const session = sessions.get(socket.id);
      if (!session) return;
      const rid = (payload && payload.roomId) || session.roomId;
      if (!rid) return;
      let set = roomTypers.get(rid);
      if (!set) { set = new Set(); roomTypers.set(rid, set); }
      set.add(session.username);
      io.to(rid).emit('typing:update', Array.from(set));
    } catch (err) { console.error('typing:start err', err); }
  });

  socket.on('typing:stop', (payload) => {
    try {
      const session = sessions.get(socket.id);
      if (!session) return;
      const rid = (payload && payload.roomId) || session.roomId;
      if (!rid) return;
      const set = roomTypers.get(rid);
      if (!set) return;
      set.delete(session.username);
      io.to(rid).emit('typing:update', Array.from(set));
    } catch (err) { console.error('typing:stop err', err); }
  });

  socket.on('admin:delete', async (payload, ack) => {
    try {
      if (!isAdminPayload(payload)) return ack && ack({ ok: false, error: 'unauthorized' });
      const { roomId, messageId } = payload || {};
      if (!roomId || !messageId) return ack && ack({ ok: false, error: 'roomId and messageId required' });
      const room = findRoomById(roomId);
      if (!room) return ack && ack({ ok: false, error: 'room not found' });
      const origLen = room.history.length;
      room.history = room.history.filter(m => m.id !== messageId);
      if (room.history.length === origLen) return ack && ack({ ok: false, error: 'message id not found' });
      scheduleWriteData();
      io.to(roomId).emit('message:deleted', { id: messageId, byAdmin: true });
      io.to(roomId).emit('system:notice', { text: `A message was removed by an admin.` });
      if (ack) ack({ ok: true });
    } catch (err) { console.error('admin delete error', err); if (ack) ack({ ok: false, error: 'server error' }); }
  });

  socket.on('leave', (payload, ack) => {
    try {
      const s = sessions.get(socket.id);
      if (!s) { if (ack) ack({ ok: true }); return; }
      const roomId = (payload && payload.roomId) || s.roomId;
      if (roomTypers[roomId]) roomTypers[roomId].delete(s.username);
      sessions.delete(socket.id);
      socket.leave(roomId);
      gatherPresence(roomId).then(p => io.to(roomId).emit('presence:update', p)).catch(()=>{});
      if (ack) ack({ ok: true });
    } catch (err) { console.error('leave error', err); if (ack) ack({ ok: false, error: 'server error' }); }
  });

  socket.on('disconnect', async () => {
    const s = sessions.get(socket.id);
    if (s) {
      s.lastSeen = Date.now();
      if (roomTypers[s.roomId]) {
        roomTypers[s.roomId].delete(s.username);
        io.to(s.roomId).emit('typing:update', Array.from(roomTypers[s.roomId]));
      }
      try {
        const presence = await gatherPresence(s.roomId);
        io.to(s.roomId).emit('presence:update', presence);
      } catch (e) {}
      sessions.delete(socket.id);
    }
    console.log('socket disconnected', socket.id);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (build ${BUILD_ID})`);
});
