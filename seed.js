/**
 * seed.js
 * Creates an example admin user + room and writes them to data/rooms.json.
 * Generates a fresh ECDH P-256 key pair for the room owner and stores the owner's private JWK
 * in data/seed_admin_key.json so you can import it into the browser (for demo ONLY).
 *
 * NOTE: This saves a private key to disk for convenience in the demo. For real E2E,
 * private keys should never be sent to the server or written to server storage.
 */

const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { webcrypto } = require('crypto');

const DATA_FILE = path.join(__dirname, 'data', 'rooms.json');
const OUT_KEY_FILE = path.join(__dirname, 'data', 'seed_admin_key.json');

async function generateOwnerKeys() {
  const subtle = webcrypto.subtle;
  const kp = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const pub = await subtle.exportKey('jwk', kp.publicKey);
  const priv = await subtle.exportKey('jwk', kp.privateKey);
  return { publicJwk: pub, privateJwk: priv };
}

async function seed() {
  const ownerName = 'seed_admin';
  const roomName = 'Seed Room (demo)';

  const keys = await generateOwnerKeys();
  const inviteToken = uuidv4().slice(0, 8);
  const roomId = uuidv4();

  const room = {
    id: roomId,
    name: roomName,
    isPrivate: true,
    owner: ownerName,
    inviteToken,
    roomPublicJwk: keys.publicJwk,
    banned: [],
    membersPublic: {},
    history: []
  };

  // write rooms
  const data = { rooms: [room] };
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  // write owner private key to file for demo import
  fs.writeFileSync(OUT_KEY_FILE, JSON.stringify({ owner: ownerName, roomId, privateJwk: keys.privateJwk, publicJwk: keys.publicJwk, inviteToken }, null, 2));

  console.log('Seed complete.');
  console.log('Room ID:', roomId);
  console.log('Invite token:', inviteToken);
  console.log('Seed owner key written to data/seed_admin_key.json — import this key into the browser to act as the room owner for the demo.');
}

seed().catch(err => {
  console.error(err);
  process.exit(1);
});
