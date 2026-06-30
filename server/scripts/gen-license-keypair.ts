/**
 * Generate the Ed25519 license-signing keypair. UniQueS founder-only.
 *
 *   npx tsx scripts/gen-license-keypair.ts [--force]
 *
 * Writes the PRIVATE key to server/.license-signing-key.pem (gitignored, 0600)
 * and prints the PUBLIC key to paste into src/license/keys.ts. Run ONCE at setup;
 * re-running needs --force and ROTATES the key, invalidating every key already
 * issued under the old pair. Back up the .pem somewhere safe — losing it means
 * you can never issue or renew a key under the shipped public key again.
 */
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync, existsSync } from "node:fs";

const OUT = new URL("../.license-signing-key.pem", import.meta.url);

if (existsSync(OUT) && !process.argv.includes("--force")) {
  console.error(
    `Refusing to overwrite ${OUT.pathname}\n` +
      `It already exists. Pass --force to ROTATE (this invalidates all issued keys).`,
  );
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
writeFileSync(OUT, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });

console.log(`Private key written to ${OUT.pathname} (gitignored — back this up securely).\n`);
console.log("Paste this PUBLIC key into src/license/keys.ts → EMBEDDED_PUBLIC_KEY_PEM:\n");
console.log(publicKey.export({ type: "spki", format: "pem" }).toString());
