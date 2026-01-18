// public/mainv6.js
// Client app modified to unwrap server-wrapped room key on join,
// and then use the room symmetric AES-GCM key to encrypt/decrypt messages.
// UI and user flows unchanged.

(() => {
  let socket = null;
  let myUsername = null;
  let myKeyPair = null; // { publicJwk, privateJwk }
  let currentRoom = null;
  let roomAesKey = null; // CryptoKey AES-GCM for encrypt/decrypt

  /* crypto helpers */
  function toBase64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function fromBase64(str) { const s = atob(str); const arr = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) arr[i] = s.charCodeAt(i); return arr.buffer; }
  async function exportJwk(key) { return crypto.subtle.exportKey('jwk', key); }
  async function importPublicJwk(jwk) { return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []); }
  async function importPrivateJwk(jwk) { return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey','deriveBits']); }

  async function ensureClientKeys() {
    const saved = localStorage.getItem('e2e_keypair');
    if (saved) { myKeyPair = JSON.parse(saved); return myKeyPair; }
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey','deriveBits']);
    const pub = await exportJwk(kp.publicKey);
    const priv = await exportJwk(kp.privateKey);
    myKeyPair = { publicJwk: pub, privateJwk: priv };
    localStorage.setItem('e2e_keypair', JSON.stringify(myKeyPair));
    return myKeyPair;
  }

  // Derive an AES-GCM 256 key from ECDH between our privateJwk and otherPublicJwk
  async function deriveAesKeyFromECDH(privateJwk, otherPublicJwk) {
    const priv = await importPrivateJwk(privateJwk);
    const pub = await importPublicJwk(otherPublicJwk);
    const derived = await crypto.subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return derived;
  }

  // Unwrap/Decrypt wrappedRoomKey sent by server (wrapped with ECDH(serverPriv, clientPub))
  // wrappedRoomKeyBase64, ivBase64: base64 strings
  async function unwrapRoomKeyFromServer(privateJwk, serverPublicJwk, wrappedRoomKeyBase64, ivBase64) {
    if (!wrappedRoomKeyBase64 || !ivBase64) return null;
    try {
      const wrappingKey = await deriveAesKeyFromECDH(privateJwk, serverPublicJwk);
      const wrappedBuf = fromBase64(wrappedRoomKeyBase64);
      const iv = new Uint8Array(fromBase64(ivBase64));
      // unwrap: server wrapped the raw symmetric key (32 bytes) with AES-GCM; we decrypt to get the raw key
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, wrappedBuf);
      // import the raw room key as AES-GCM CryptoKey for later encrypt/decrypt usage
      const roomKey = await crypto.subtle.importKey('raw', plain, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
      return roomKey;
    } catch (e) {
      console.error('unwrapRoomKeyFromServer error', e);
      return null;
    }
  }

  // Utility: create a new AES-GCM key from raw 32-byte buffer (BufferSource)
  async function importRawAesKey(rawBuf) {
    return crypto.subtle.importKey('raw', rawBuf, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  // Encrypt plain text with roomAesKey (AES-GCM)
  async function encryptForRoom(aesKey, text) {
    const enc = new TextEncoder().encode(text);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc);
    return { ciphertext: toBase64(ct), iv: toBase64(iv) };
  }

  // Decrypt ciphertext with roomAesKey
  async function decryptFromRoom(aesKey, ciphertextBase64, ivBase64) {
    try {
      const ct = fromBase64(ciphertextBase64);
      const iv = fromBase64(ivBase64);
      const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
      return new TextDecoder().decode(plainBuf);
    } catch (e) {
      return '[cannot decrypt]';
    }
  }

  /* DOM helpers (unchanged) */
  function $(id) { return document.getElementById(id); }
  function hide(id) { const el = $(id); if (el) el.style.display = 'none'; }
  function show(id) { const el = $(id); if (el) el.style.display = ''; }
  function escapeHtml(s){ if(!s) return ''; return s.toString().replace(/[&<>"']/g, (m)=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

  function appendMessage(msg, isOwn) {
    const container = $('messages');
    const el = document.createElement('div');
    el.dataset.id = msg.id;
    el.className = isOwn ? 'msg own' : 'msg other';
    el.setAttribute('tabindex', '0');
    el.innerText = `${msg.from}: ${msg.text}`;
    el.addEventListener('dblclick', () => { copyToClipboard(msg.text); showSystemNotice('Message copied'); });
    el.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c') {
        e.preventDefault();
        copyToClipboard(msg.text);
        showSystemNotice('Message copied');
      }
    });
    container.appendChild(el);
    container.scrollTop = container.scrollHeight;
  }

  function showSystemNotice(txt) {
    const el = $('messages');
    if (!el) return;
    const d = document.createElement('div');
    d.className = 'sys';
    d.innerText = txt;
    el.appendChild(d);
    el.scrollTop = el.scrollHeight;
  }

  function copyToClipboard(text) { try { navigator.clipboard.writeText(text); } catch (e) {} }

  function saveLocalMsg(roomId, msg) {
    try {
      const key = `chat_history_${roomId}`;
      const arr = JSON.parse(localStorage.getItem(key) || '[]');
      if (!arr.find(x => x.id === msg.id)) arr.push(msg);
      localStorage.setItem(key, JSON.stringify(arr));
    } catch (e) { console.error('saveLocalMsg', e); }
  }
  async function loadLocalMsgs(roomId) { try { const key = `chat_history_${roomId}`; return JSON.parse(localStorage.getItem(key) || '[]'); } catch (e) { return []; } }

  /* socket */
  function ensureSocket() {
    if (socket && socket.connected) return socket;
    socket = io({ transports: ['polling', 'websocket'], timeout: 20000, reconnectionAttempts: 5 });

    socket.on('connect', () => console.log('socket connected', socket.id));
    socket.on('presence:update', (p) => {
      const el = $('presence'); if (!el) return;
      el.innerText = `Members: ${ (p.members || []).map(m => m.username + (m.online ? ' (online)' : '')).join(', ') }`;
    });
    socket.on('system:notice', (n) => { if (n && n.text) showSystemNotice(n.text); });
    socket.on('room:meta', (meta) => {
      if (!meta) return;
      if (meta.inviteToken) { $('room-invite-token').innerText = meta.inviteToken; $('room-invite').style.display = ''; } else { $('room-invite').style.display = 'none'; }
    });
    socket.on('message:new', async (m) => {
      if (!currentRoom) return;
      if (m.ciphertext && roomAesKey) {
        const text = await decryptFromRoom(roomAesKey, m.ciphertext, m.iv);
        appendMessage({ id: m.id, from: m.from, text }, m.from === myUsername);
        saveLocalMsg(currentRoom.id, m);
      } else appendMessage({ id: m.id, from: m.from, text: '[no ciphertext]' }, m.from === myUsername);
    });
    socket.on('typing:update', (arr) => {
      const el = $('typing'); if (!el) return; el.innerText = arr && arr.length ? `${arr.join(', ')} is typing...` : '';
    });
    socket.on('message:deleted', (d) => {
      if (!d || !d.id) return;
      const li = document.querySelector(`[data-id="${d.id}"]`); if (li) li.remove();
      showSystemNotice(d.byAdmin ? 'Message removed by admin' : 'Message removed');
    });
    return socket;
  }

  function waitForSocketConnection(timeoutMs = 10000) {
    if (socket && socket.connected) return Promise.resolve();
    return new Promise((resolve, reject) => {
      if (!socket) ensureSocket();
      const onCon = () => { cleanup(); resolve(); };
      const onErr = (err) => { cleanup(); reject(err || new Error('socket error')); };
      const timer = setTimeout(() => { cleanup(); reject(new Error('socket connect timeout')); }, timeoutMs);
      function cleanup() { clearTimeout(timer); socket.off('connect', onCon); socket.off('connect_error', onErr); }
      socket.on('connect', onCon); socket.on('connect_error', onErr);
    });
  }

  /* API */
  async function loadRooms() {
    try {
      const res = await fetch('/api/rooms');
      const json = await res.json();
      renderRooms(json.rooms || []);
    } catch (e) {
      console.error('loadRooms', e);
      showSystemNotice('Could not load rooms');
    }
  }

  function renderRooms(list) {
    const container = $('rooms-list'); container.innerHTML = '';
    for (const r of list) {
      const li = document.createElement('li'); li.className = 'room-row';
      li.innerHTML = `<div class="left"><div><strong>${escapeHtml(r.name)}</strong><div class="room-meta">${escapeHtml(r.owner)}</div></div></div><div><button data-id="${r.id}" data-private="${r.isPrivate ? 1 : 0}">Join</button></div>`;
      const btn = li.querySelector('button');
      btn.addEventListener('click', async () => {
        try {
          btn.disabled = true; btn.innerText = 'Joining...';
          const listedPrivate = btn.dataset.private === '1';
          if (listedPrivate) {
            const chosen = prompt('This room is private. Paste invite token:');
            if (!chosen) { showSystemNotice('Invite token required'); throw new Error('invite token required'); }
            await doJoin(chosen);
          } else {
            await doJoin(btn.dataset.id);
          }
        } catch (err) {
          console.error('join err', err);
          showSystemNotice('Join failed: ' + (err && err.error ? err.error : (err && err.message) || 'unknown'));
        } finally {
          btn.disabled = false; btn.innerText = 'Join';
        }
      });
      container.appendChild(li);
    }
  }

  /* join flow (with server wrapping) */
  async function doJoin(roomIdOrToken) {
    if (!myUsername) return alert('login first');
    await ensureClientKeys();
    ensureSocket();
    try { await waitForSocketConnection(10000); } catch (e) { console.warn('socket not connected', e); }
    const attemptJoin = (idOrToken) => new Promise((resolve, reject) => {
      let timedOut = false; const timer = setTimeout(() => { timedOut = true; reject({ error: 'join timeout' }); }, 15000);
      try {
        socket.emit('join', { roomIdOrToken: idOrToken, username: myUsername, publicJwk: myKeyPair.publicJwk }, (ack) => {
          clearTimeout(timer); if (timedOut) return;
          resolve(ack);
        });
      } catch (e) {
        clearTimeout(timer); reject(e);
      }
    });

    let ack;
    try { ack = await attemptJoin(roomIdOrToken); } catch (e) { throw e; }
    if (ack && !ack.ok && ack.error === 'room is private; provide invite token') {
      const token = prompt('Room is private — paste invite token:'); if (!token) throw new Error('invite token required');
      try { ack = await attemptJoin(token); } catch (e) { throw e; }
    }
    if (!ack || !ack.ok) throw ack || new Error('join failed');

    currentRoom = ack.data.room;
    $('room-name').innerText = currentRoom.name + (currentRoom.isPrivate ? ' (private)' : '');
    if (currentRoom.inviteToken) { $('room-invite-token').innerText = currentRoom.inviteToken; $('room-invite').style.display = ''; } else { $('room-invite').style.display = 'none'; }

    // Important: server provides serverPublicJwk + wrappedRoomKey + wrappedRoomKeyIv
    // We must derive the AES key via ECDH(myPriv, serverPub) and decrypt wrappedRoomKey to get the raw room symmetric key,
    // then import that raw key as AES-GCM CryptoKey and store in roomAesKey.
    try {
      if (currentRoom.wrappedRoomKey && currentRoom.wrappedRoomKeyIv && currentRoom.serverPublicJwk) {
        roomAesKey = await unwrapRoomKeyFromServer(myKeyPair.privateJwk, currentRoom.serverPublicJwk, currentRoom.wrappedRoomKey, currentRoom.wrappedRoomKeyIv);
        if (!roomAesKey) { console.error('Failed to unwrap room key'); alert('Unable to derive room key — you will not be able to decrypt messages.'); }
      } else if (currentRoom.roomPublicJwk) {
        // Fallback for older server versions: derive from roomPublicJwk (older behavior)
        try {
          roomAesKey = await deriveAesKeyFromECDH(myKeyPair.privateJwk, currentRoom.roomPublicJwk);
        } catch (e) {
          console.error('fallback derive failed', e);
        }
      } else {
        console.warn('No wrapped room key provided by server');
      }
    } catch (e) {
      console.error('deriveRoomKey error', e);
      alert('Unable to derive room key');
      return;
    }

    $('messages').innerHTML = '';
    for (const m of ack.data.history || []) {
      const text = m.ciphertext && roomAesKey ? await decryptFromRoom(roomAesKey, m.ciphertext, m.iv) : (m.text || '[no ciphertext]');
      appendMessage({ id: m.id, from: m.from, text }, m.from === myUsername);
    }
    const local = await loadLocalMsgs(currentRoom.id);
    for (const m of local) {
      if (!ack.data.history.find(h => h.id === m.id)) {
        const text = m.ciphertext && roomAesKey ? await decryptFromRoom(roomAesKey, m.ciphertext, m.iv) : (m.text || '[local]');
        appendMessage({ id: m.id, from: m.from, text }, m.from === myUsername);
      }
    }

    hide('login'); hide('lobby'); show('room');
    setTimeout(() => { const el = $('message-input'); if (el) el.focus(); }, 50);
  }

  async function doCreateRoom() {
    const name = $('create-name').value.trim();
    const isPrivate = $('create-private').checked;
    const customToken = $('create-token').value.trim();
    if (!name) return alert('room name required');
    await ensureClientKeys();
    try {
      const payload = { name, isPrivate: !!isPrivate, owner: myUsername, ownerPublicJwk: myKeyPair.publicJwk };
      if (isPrivate && customToken) payload.inviteToken = customToken;
      const res = await fetch('/api/rooms', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
      const json = await res.json();
      if (json && json.roomId) {
        showSystemNotice(`Room created. ID: ${json.roomId}${json.inviteToken ? ' (invite: ' + json.inviteToken + ')' : ''}`);
        await loadRooms();
        if (isPrivate && json.inviteToken) await doJoin(json.inviteToken); else await doJoin(json.roomId);
      } else {
        showSystemNotice('Create failed');
      }
    } catch (e) {
      console.error('createRoom err', e);
      showSystemNotice('create failed');
    }
  }

  async function doLeave() {
    if (!socket) { sessionsCleanup(); return; }
    socket.emit('leave', { roomId: currentRoom && currentRoom.id }, (ack) => {
      console.log('leave ack', ack);
      sessionsCleanup();
    });
    sessionsCleanup();
  }
  function sessionsCleanup() { currentRoom = null; roomAesKey = null; hide('room'); show('lobby'); $('messages').innerHTML = ''; $('room-invite').style.display = 'none'; $('room-invite-token').innerText = ''; }

  async function sendMessage(text) {
    if (!roomAesKey || !currentRoom) { showSystemNotice('Not in a room'); return; }
    const enc = await encryptForRoom(roomAesKey, text);
    const payload = { roomId: currentRoom.id, from: myUsername, ciphertext: enc.ciphertext, iv: enc.iv, ts: Date.now() };
    socket.emit('message:send', payload, (ack) => {
      if (ack && ack.ok) {
        appendMessage({ id: ack.id, from: myUsername, text }, true);
        saveLocalMsg(currentRoom.id, { id: ack.id, from: myUsername, ciphertext: enc.ciphertext, iv: enc.iv, ts: Date.now() });
      } else {
        showSystemNotice('Send failed: ' + (ack && ack.error));
      }
    });
  }

  /* UI wiring (unchanged) */
  function initUI() {
    $('create-private').addEventListener('change', (e) => { $('create-token').style.display = e.target.checked ? '' : 'none'; });
    $('btn-login').addEventListener('click', async () => {
      const u = $('username').value.trim(); if (!u) return alert('pick a username'); myUsername = u; await ensureClientKeys(); hide('login'); show('lobby'); await loadRooms();
    });
    $('btn-create-room').addEventListener('click', async () => { await doCreateRoom(); });
    $('btn-leave').addEventListener('click', async () => { await doLeave(); });
    $('btn-send').addEventListener('click', async () => {
      const text = $('message-input').value.replace(/\r/g, '').trim(); if (!text) return; $('message-input').value = ''; await sendMessage(text);
    });

    $('message-input').addEventListener('keydown', async (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        const txt = $('message-input').value.replace(/\r/g, '').trim();
        if (!txt) return;
        $('message-input').value = '';
        await sendMessage(txt);
      }
    });

    $('message-input').addEventListener('input', () => {
      if (!socket || !currentRoom) return;
      socket.emit('typing:start', { roomId: currentRoom.id });
      clearTimeout(window._typingTimer);
      window._typingTimer = setTimeout(() => socket.emit('typing:stop', { roomId: currentRoom.id }), 1500);
    });

    $('copy-invite').addEventListener('click', () => {
      const token = $('room-invite-token').innerText; if (token) { copyToClipboard(token); showSystemNotice('Invite copied'); }
    });

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const el = $('message-input'); if (el) el.focus();
      }
    });
  }

  window.addEventListener('load', initUI);
})();
