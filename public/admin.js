// public/admin.js
// Simple admin page client: login -> stores adminToken in sessionStorage -> uses it for admin HTTP calls and for admin impersonate via socket.io

(() => {
  let adminToken = sessionStorage.getItem('adminToken') || null;
  let adminSocket = null;

  function $(id){ return document.getElementById(id); }
  function showLogin(){ $('admin-login').style.display=''; $('admin-panel').style.display='none'; }
  function showPanel(){ $('admin-login').style.display='none'; $('admin-panel').style.display=''; }

  async function api(path, opts = {}) {
    opts.headers = opts.headers || {};
    if (adminToken) opts.headers['x-admin-token'] = adminToken;
    const res = await fetch(path, opts);
    if (!res.ok) { const txt = await res.text().catch(()=>null); throw new Error((await res.json().catch(()=>({error:txt}))).error || res.statusText); }
    return res.json();
  }

  async function login() {
    const u = $('admin-username').value.trim();
    const p = $('admin-password').value;
    if (!u || !p) return alert('username & password required');
    try {
      const j = await api('/api/admin/login', { method:'POST', headers:{ 'content-type':'application/json' }, body: JSON.stringify({ username: u, password: p }) });
      adminToken = j.adminToken;
      sessionStorage.setItem('adminToken', adminToken);
      showPanel();
      listRooms();
      addNotice('Logged in as admin');
    } catch (e) { addNotice('Login failed: ' + e.message); }
  }

  function addNotice(txt) { const n = $('admin-notices'); n.innerText = txt; setTimeout(()=>{ if(n.innerText===txt) n.innerText=''; }, 8000); }

  async function listRooms() {
    try {
      const j = await api('/api/admin/rooms');
      const rooms = j.rooms || [];
      const ul = $('admin-rooms'); ul.innerHTML = '';
      const sel = $('delete-room-select'); sel.innerHTML = '<option value="">Select room to delete</option>';
      for (const r of rooms) {
        const li = document.createElement('li');
        li.innerText = `${r.name} (${r.id}) - owner: ${r.owner} ${r.isPrivate ? '[private]' : ''}`;
        const btnImp = document.createElement('button'); btnImp.innerText = 'Impersonate'; btnImp.addEventListener('click', ()=>{ $('imp-room').value = r.id; $('imp-username').value = prompt('Username to impersonate (e.g. alice):'); });
        li.appendChild(btnImp);
        ul.appendChild(li);
        const opt = document.createElement('option'); opt.value = r.id; opt.innerText = `${r.name} (${r.id})`; sel.appendChild(opt);
      }
      addNotice(`Loaded ${rooms.length} rooms`);
    } catch (e) { addNotice('Could not load rooms: ' + e.message); }
  }

  async function impersonate() {
    const room = $('imp-room').value.trim(); const uname = $('imp-username').value.trim();
    if (!room || !uname) return alert('room and username required');
    // generate ephemeral key pair to impersonate (publicJwk)
    try {
      const kp = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveKey','deriveBits']);
      const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
      // connect admin socket if not present
      if (!adminSocket || !adminSocket.connected) {
        adminSocket = io({ transports:['polling','websocket'], timeout:20000, reconnectionAttempts:5 });
      }
      // emit admin:impersonate with adminToken
      adminSocket.emit('admin:impersonate', { adminToken, roomIdOrToken: room, username: uname, publicJwk: pub }, (ack) => {
        if (!ack || !ack.ok) return addNotice('Impersonate failed: ' + (ack && ack.error));
        addNotice(`Impersonated ${uname} into ${room}. You are connected on socket id ${adminSocket.id}`);
        // Optionally open a new window that loads the app and uses this socket? For simplicity, admin will see confirmation.
      });
    } catch (e) { addNotice('Impersonation failed: ' + e.message); console.error(e); }
  }

  async function syncChats() {
    const txt = $('sync-json').value.trim();
    if (!txt) return alert('paste rooms JSON');
    try {
      const obj = JSON.parse(txt);
      if (!Array.isArray(obj)) return alert('rooms JSON must be an array');
      const res = await api('/api/admin/sync-chats', { method:'POST', headers:{ 'content-type':'application/json' }, body: JSON.stringify({ rooms: obj }) });
      addNotice(`Sync OK: ${res.count} rooms`);
      listRooms();
    } catch (e) { addNotice('Sync failed: ' + e.message); }
  }

  async function uploadBanlist() {
    const txt = $('ban-json').value.trim();
    if (!txt) return alert('paste banlist JSON array');
    try {
      const arr = JSON.parse(txt);
      if (!Array.isArray(arr)) return alert('banlist must be an array');
      const res = await api('/api/admin/upload-banlist', { method:'POST', headers:{ 'content-type':'application/json' }, body: JSON.stringify({ banned: arr }) });
      addNotice(`Banlist updated (${res.count})`);
    } catch (e) { addNotice('Upload banlist failed: ' + e.message); }
  }

  async function viewBanlist() {
    try {
      const res = await api('/api/admin/banlist');
      alert('Banned users:\n' + JSON.stringify(res.banned || [], null, 2));
    } catch (e) { addNotice('Could not load banlist: ' + e.message); }
  }

  async function deleteSelectedRoom() {
    const sel = $('delete-room-select'); const rid = sel.value;
    if (!rid) return alert('select a room');
    if (!confirm('Delete room ' + rid + ' permanently?')) return;
    try {
      const res = await api('/api/admin/delete-room', { method:'POST', headers:{ 'content-type':'application/json' }, body: JSON.stringify({ roomId: rid }) });
      addNotice('Room deleted');
      listRooms();
    } catch (e) { addNotice('Delete failed: ' + e.message); }
  }

  function downloadRooms() {
    api('/api/admin/rooms').then(j => {
      const a = document.createElement('a');
      a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(j.rooms || [], null, 2));
      a.download = 'rooms.json';
      document.body.appendChild(a); a.click(); a.remove();
    }).catch(e => addNotice('Download failed: ' + e.message));
  }

  // wire UI
  window.addEventListener('load', () => {
    if (adminToken) showPanel(); else showLogin();
    $('admin-login-btn').addEventListener('click', login);
    $('btn-refresh-rooms').addEventListener('click', listRooms);
    $('imp-join').addEventListener('click', impersonate);
    $('btn-sync').addEventListener('click', syncChats);
    $('btn-upload-ban').addEventListener('click', uploadBanlist);
    $('btn-view-ban').addEventListener('click', viewBanlist);
    $('btn-delete-room').addEventListener('click', deleteSelectedRoom);
    $('btn-download-rooms').addEventListener('click', downloadRooms);
    $('btn-refresh-rooms').click();
  });
})();
