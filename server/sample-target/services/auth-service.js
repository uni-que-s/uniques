// Customer authentication service — handles login tokens and session signing.
const crypto = require("crypto");

function generateSigningKeys() {
  // Legacy: RSA-2048 used to sign all customer session JWTs.
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

function hashPassword(pw, salt) {
  // Weak: SHA-1 still used for legacy password records.
  return crypto.createHash("sha1").update(pw + salt).digest("hex");
}

function legacySessionCipher(key) {
  // Triple-DES protecting cached session blobs.
  return crypto.createCipheriv("des-ede3-cbc", key, Buffer.alloc(8));
}

module.exports = { generateSigningKeys, hashPassword, legacySessionCipher };
