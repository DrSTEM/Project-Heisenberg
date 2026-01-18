const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');

(async () => {
  const kp = await webcrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const publicJwk = await webcrypto.subtle.exportKey('jwk', kp.publicKey);
  const privateJwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey);

  const out = { publicJwk, privateJwk };

  const dir = path.join(__dirname, 'data');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);

  fs.writeFileSync(
    path.join(dir, 'server_key.json'),
    JSON.stringify(out, null, 2),
    'utf8'
  );

  console.log('✅ data/server_key.json created');
})();
