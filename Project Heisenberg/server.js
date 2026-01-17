// server.js
// Chat server with:
// - creator-provided invite tokens and creator auto-join
// - admin sessions (username/password -> adminToken) and admin endpoints
// - admin impersonation support via adminToken or ADMIN_SECRET
// - banlist upload / global bans
// - atomic room writes, BUILD_ID cache-busting injection for client

const express = require('express');
const http = require('http');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 8080;
const DATA_PATH = path.join(__dirname, 'data', 'rooms.json');
const BAN_PATH = path.join(__dirname, 'data', 'banned.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'dev-secret';

const BUILD_ID = Date.now();
console.log('BUILD_ID', BUILD_ID);

// in-memory maps
const sessions = new Map(); // socketId -> { username, roomId, lastSeen, isAdmin }
const roomTypers = new Map(); // roomId -> Set(username)
const adminSessions = new Map(); // adminToken -> { createdAt }

async function readData() {
  try {
    const raw = await fs.readFile(DATA_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === 'ENOENT') return { rooms: [] };
    console.error('readData error', e);
    throw e;
  }
}

async function writeData(data) {
  try {
    const tmp = DATA_PATH + '.tmp';
    await fs.mkdir(path.dirname(DATA_PATH), { recursive: true });
    await fs.writeFile(tmp, JSON.stringify(data, null, 2), 'utf8');
    await fs.rename(tmp, DATA_PATH);
  } catch (e) {
    console.error('writeData error', e);
    throw e;
  }
}

async function readBanList() {
  try {
    const raw = await fs.readFile(BAN_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    console.error('readBanList error', e);
    return [];
  }
}

async function writeBanList(list) {
  try {
    await fs.mkdir(path.dirname(BAN_PATH), { recursive: true });
    await fs.writeFile(BAN_PATH + '.tmp', JSON.stringify(list, null, 2), 'utf8');
    await fs.rename(BAN_PATH + '.tmp', BAN_PATH);
  } catch (e) {
    console.error('writeBanList error', e);
    throw e;
  }
}

function findRoomById(data, id) {
  return data.rooms.find(r => r.id === id) || null;
}
function findRoomByToken(data, token) {
  if (!token) return null;
  return data.rooms.find(r => r.inviteToken === token) || null;
}

async function gatherPresence(roomId) {
  const data = await readData();
  const room = data.rooms.find(r => r.id === roomId);
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

/* ---------- express + static ---------- */
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

// no-cache middleware & static
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});
app.use(express.static(PUBLIC_DIR, { index: false, etag: false, lastModified: false }));
app.use(bodyParser.json({ limit: '5mb' }));

/* index with BUILD_ID + cache-clear bootstrap */
app.get(['/', '/index.html'], async (req, res) => {
  try {
    const htmlPath = path.join(PUBLIC_DIR, 'index.html');
    let html = await fs.readFile(htmlPath, 'utf8');

    const bootstrap = `
<script>
(function(){
  try {
    const SERVER_BUILD = ${BUILD_ID};
    const KEY = 'APP_BUILD_ID';
    const prev = localStorage.getItem(KEY);
    if (prev && Number(prev) !== SERVER_BUILD) {
      if ('serviceWorker' in navigator) navigator.serviceWorker.getRegistrations().then(regs=>regs.forEach(r=>r.unregister())).catch(()=>{});
      if (window.caches && caches.keys) caches.keys().then(keys=>Promise.all(keys.map(k=>caches.delete(k)))).catch(()=>{});
      localStorage.setItem(KEY, String(SERVER_BUILD));
      if (!sessionStorage.getItem('reloaded_for_build')) { sessionStorage.setItem('reloaded_for_build','1'); window.location.reload(true); } else { sessionStorage.removeItem('reloaded_for_build'); }
    } else { localStorage.setItem(KEY, String(SERVER_BUILD)); }
  } catch(e) { console.warn('bootstrap', e); }
})();
</script>
`;

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

// serve mainv6 explicitly with no-cache
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

// admin UI
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

/* ---------- API endpoints ---------- */

// simple version
app.get('/_version', (req, res) => res.json({ build: BUILD_ID, started: new Date().toISOString(), pid: process.pid }));

// list rooms
app.get('/api/rooms', async (req, res) => {
  try {
    const data = await readData();
    const rooms = (data.rooms || []).map(r => ({
      id: r.id,
      name: r.name,
      isPrivate: !!r.isPrivate,
      owner: r.owner,
      hasInvite: !!r.inviteToken
    }));
    res.json({ rooms });
  } catch (e) {
    console.error('/api/rooms error', e);
    res.status(500).json({ error: 'server error' });
  }
});

// create room (accept optional inviteToken from creator)
app.post('/api/rooms', async (req, res) => {
  try {
    const { name, isPrivate, owner, ownerPublicJwk, inviteToken } = req.body || {};
    if (!name || !owner || !ownerPublicJwk) return res.status(400).json({ error: 'name, owner, ownerPublicJwk required' });

    const data = await readData();
    const id = uuidv4();
    let token = null;
    if (isPrivate) {
      if (inviteToken && typeof inviteToken === 'string' && inviteToken.trim().length >= 4 && inviteToken.trim().length <= 64) {
        token = inviteToken.trim();
      } else {
        token = Math.random().toString(36).slice(2, 10);
      }
    }

    const room = {
      id,
      name,
      isPrivate: !!isPrivate,
      owner,
      inviteToken: token || null,
      roomPublicJwk: ownerPublicJwk,
      banned: [],
      membersPublic: { [owner]: ownerPublicJwk }, // persist owner immediately so creator not locked out
      history: []
    };

    data.rooms.push(room);
    await writeData(data);
    return res.json({ roomId: id, inviteToken: token || null });
  } catch (e) {
    console.error('POST /api/rooms error', e);
    res.status(500).json({ error: 'server error' });
  }
});

/* ---------- admin HTTP endpoints (require adminToken header) ---------- */

function verifyAdminToken(req) {
  const token = req.get('x-admin-token') || '';
  if (!token) return false;
  return adminSessions.has(token);
}

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    if (username !== ADMIN_USER || password !== ADMIN_PASS) return res.status(403).json({ error: 'unauthorized' });

    const token = uuidv4();
    adminSessions.set(token, { createdAt: Date.now() });
    return res.json({ adminToken: token });
  } catch (e) {
    console.error('admin login error', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  try {
    const token = req.get('x-admin-token') || '';
    if (token && adminSessions.has(token)) adminSessions.delete(token);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server error' }); }
});

// Replace rooms dataset (sync)
app.post('/api/admin/sync-chats', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const { rooms } = req.body || {};
    if (!Array.isArray(rooms)) return res.status(400).json({ error: 'rooms array required' });
    const data = { rooms: rooms.map(r => ({
      id: r.id || uuidv4(),
      name: r.name || 'room',
      isPrivate: !!r.isPrivate,
      owner: r.owner || 'owner',
      inviteToken: r.inviteToken || null,
      roomPublicJwk: r.roomPublicJwk || null,
      banned: r.banned || [],
      membersPublic: r.membersPublic || {},
      history: r.history || []
    }))};
    await writeData(data);
    return res.json({ ok: true, count: data.rooms.length });
  } catch (e) {
    console.error('admin sync error', e);
    res.status(500).json({ error: 'server error' });
  }
});

// delete a room permanently
app.post('/api/admin/delete-room', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const { roomId } = req.body || {};
    if (!roomId) return res.status(400).json({ error: 'roomId required' });
    const data = await readData();
    const idx = data.rooms.findIndex(r => r.id === roomId);
    if (idx === -1) return res.status(404).json({ error: 'room not found' });
    data.rooms.splice(idx, 1);
    await writeData(data);
    // force clients in that room to receive a notice
    io.to(roomId).emit('system:notice', { text: 'This room has been deleted by an admin.' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('admin delete-room error', e);
    res.status(500).json({ error: 'server error' });
  }
});

// upload/replace banlist (body: { banned: ['user1','user2'] } OR text JSON)
app.post('/api/admin/upload-banlist', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const { banned } = req.body || {};
    if (!Array.isArray(banned)) return res.status(400).json({ error: 'banned array required' });
    await writeBanList(banned);
    return res.json({ ok: true, count: banned.length });
  } catch (e) {
    console.error('upload banlist error', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/admin/banlist', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const list = await readBanList();
    res.json({ banned: list });
  } catch (e) {
    console.error('get banlist error', e);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/admin/rooms', async (req, res) => {
  try {
    if (!verifyAdminToken(req) && req.get('x-admin-secret') !== ADMIN_SECRET) return res.status(403).json({ error: 'unauthorized' });
    const data = await readData();
    res.json({ rooms: data.rooms || [] });
  } catch (e) {
    console.error('admin rooms error', e);
    res.status(500).json({ error: 'server error' });
  }
});

/* ---------------- Socket.IO ---------------- */
io.on('connection', (socket) => {
  console.log('socket connected', socket.id);

  // Accept admin token in socket admin events (payload.adminToken) OR adminSecret
  function isAdminPayload(payload) {
    if (!payload) return false;
    if (payload.adminSecret && payload.adminSecret === ADMIN_SECRET) return true;
    if (payload.adminToken && adminSessions.has(payload.adminToken)) return true;
    return false;
  }

  socket.on('join', async (payload, ack) => {
    try {
      const { roomIdOrToken, username, publicJwk } = payload || {};
      if (!roomIdOrToken || !username || !publicJwk) {
        if (ack) ack({ ok: false, error: 'roomIdOrToken, username, publicJwk required' });
        return;
      }

      const bannedList = await readBanList();
      if (Array.isArray(bannedList) && bannedList.includes(username)) {
        if (ack) ack({ ok: false, error: 'you are banned' });
        return;
      }

      const data = await readData();
      let room = findRoomById(data, roomIdOrToken);
      let usedToken = false;
      if (!room) {
        room = findRoomByToken(data, roomIdOrToken);
        usedToken = !!room;
      }
      if (!room) {
        if (ack) ack({ ok: false, error: 'room not found' });
        return;
      }

      if (room.isPrivate) {
        const isOwner = username === room.owner;
        if (!usedToken && !isOwner && !(payload && payload._adminBypass === true)) {
          if (ack) ack({ ok: false, error: 'room is private; provide invite token' });
          return;
        }
      }

      if ((room.banned || []).includes(username)) {
        if (ack) ack({ ok: false, error: 'you are banned from this room' });
        return;
      }

      // persist member key
      room.membersPublic = room.membersPublic || {};
      room.membersPublic[username] = publicJwk;
      await writeData(data);

      socket.join(room.id);
      sessions.set(socket.id, { username, roomId: room.id, lastSeen: Date.now(), isAdmin: false });

      const presence = await gatherPresence(room.id);
      io.to(room.id).emit('presence:update', presence);
      io.to(room.id).emit('system:notice', { text: `${username} joined.` });
      io.to(room.id).emit('room:meta', { id: room.id, name: room.name, isPrivate: !!room.isPrivate, inviteToken: room.inviteToken || null, owner: room.owner });

      if (ack) ack({
        ok: true,
        data: {
          room: {
            id: room.id,
            name: room.name,
            owner: room.owner,
            isPrivate: !!room.isPrivate,
            inviteToken: room.inviteToken || null,
            roomPublicJwk: room.roomPublicJwk
          },
          history: room.history || []
        }
      });
    } catch (err) {
      console.error('join error', err);
      if (ack) ack({ ok: false, error: 'server error' });
    }
  });

  // admin impersonate via socket (accepts adminSecret or adminToken)
  socket.on('admin:impersonate', async (payload, ack) => {
    try {
      if (!isAdminPayload(payload)) return ack && ack({ ok: false, error: 'unauthorized' });
      const { roomIdOrToken, username, publicJwk } = payload || {};
      if (!roomIdOrToken || !username || !publicJwk) return ack && ack({ ok: false, error: 'roomIdOrToken, username, publicJwk required' });

      const data = await readData();
      let room = findRoomById(data, roomIdOrToken) || findRoomByToken(data, roomIdOrToken);
      if (!room) return ack && ack({ ok: false, error: 'room not found' });

      room.membersPublic = room.membersPublic || {};
      room.membersPublic[username] = publicJwk;
      await writeData(data);

      socket.join(room.id);
      sessions.set(socket.id, { username, roomId: room.id, lastSeen: Date.now(), isAdmin: true });

      const presence = await gatherPresence(room.id);
      io.to(room.id).emit('presence:update', presence);
      io.to(room.id).emit('system:notice', { text: `${username} (admin) joined.` });
      io.to(room.id).emit('room:meta', { id: room.id, name: room.name, isPrivate: !!room.isPrivate, inviteToken: room.inviteToken || null, owner: room.owner });

      if (ack) ack({ ok: true, data: { room: { id: room.id, name: room.name, owner: room.owner, isPrivate: !!room.isPrivate, inviteToken: room.inviteToken || null, roomPublicJwk: room.roomPublicJwk }, history: room.history || [] } });
    } catch (err) {
      console.error('admin impersonate err', err);
      if (ack) ack({ ok: false, error: 'server error' });
    }
  });

  // message send, typing, leave, admin delete as before, but admin delete accepts adminToken too
  socket.on('message:send', async (payload, ack) => {
    try {
      const session = sessions.get(socket.id);
      if (!session) { if (ack) ack({ ok: false, error: 'not in room' }); return; }
      const { roomId, from, ciphertext, iv, ts } = payload || {};
      if (!roomId || !from || !ciphertext || !iv || !ts) { if (ack) ack({ ok: false, error: 'bad payload' }); return; }
      const data = await readData();
      const room = data.rooms.find(r => r.id === roomId);
      if (!room) { if (ack) ack({ ok: false, error: 'room not found' }); return; }
      const message = { id: uuidv4(), from, ciphertext, iv, ts };
      room.history = room.history || [];
      room.history.push(message);
      await writeData(data);
      io.to(roomId).emit('message:new', message);
      if (ack) ack({ ok: true, id: message.id });
    } catch (err) { console.error('message:send error', err); if (ack) ack({ ok: false, error: 'server error' }); }
  });

  socket.on('typing:start', (payload) => {
    try {
      const session = sessions.get(socket.id);
      if (!session) return;
      const { roomId } = payload || {};
      const rid = roomId || session.roomId;
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
      const { roomId } = payload || {};
      const rid = roomId || session.roomId;
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
      const data = await readData();
      const room = data.rooms.find(r => r.id === roomId);
      if (!room) return ack && ack({ ok: false, error: 'room not found' });
      const origLen = room.history.length;
      room.history = room.history.filter(m => m.id !== messageId);
      if (room.history.length === origLen) return ack && ack({ ok: false, error: 'message id not found' });
      await writeData(data);
      io.to(roomId).emit('message:deleted', { id: messageId, byAdmin: true });
      io.to(roomId).emit('system:notice', { text: `A message was removed by an admin.` });
      if (ack) ack({ ok: true });
    } catch (err) { console.error('admin delete error', err); if (ack) ack({ ok: false, error: 'server error' }); }
  });

  socket.on('leave', (payload, ack) => {
    try {
      const s = sessions.get(socket.id);
      if (!s) { if (ack) ack({ ok: true }); return; }
      const roomId = payload && payload.roomId ? payload.roomId : s.roomId;
      if (roomTypers[roomId]) roomTypers[roomId].delete(s.username);
      sessions.delete(socket.id);
      socket.leave(roomId);
      gatherPresence(roomId).then(p => io.to(roomId).emit('presence:update', p)).catch(() => {});
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

/* start server */
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (build ${BUILD_ID})`);
});
