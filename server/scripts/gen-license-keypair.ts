/**
 * Generate the ML-DSA-65 (FIPS 204, post-quantum) license-signing keypair.
 * UniQueS founder-only.
 *
 *   npx tsx scripts/gen-license-keypair.ts [--force]
 *
 * Writes the 32-byte signing SEED (base64) to server/.license-signing-seed
 * (gitignored, 0600) and prints the PUBLIC key to paste into src/license/keys.ts.
 * The seed deterministically regenerates the full keypair, so it is all the
 * founder needs to keep (and MUST keep secret + backed up). Run ONCE at setup;
 * re-running needs --force and ROTATES the key, invalidating every key already
 * issued under the old pair.
 */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes } from "node:crypto";
import { writeFileSync, existsSync } from "node:fs";

const OUT = new URL("../.license-signing-seed", import.meta.url);

if (existsSync(OUT) && !process.argv.includes("--force")) {
  console.error(
    `Refusing to overwrite ${OUT.pathname}\n` +
      `It already exists. Pass --force to ROTATE (this invalidates all issued keys).`,
  );
  process.exit(1);
}

const seed = new Uint8Array(randomBytes(32));
const { publicKey } = ml_dsa65.keygen(seed);
writeFileSync(OUT, Buffer.from(seed).toString("base64"), { mode: 0o600 });

console.log(`Signing seed written to ${OUT.pathname} (gitignored — back this up securely).\n`);
console.log("Paste this PUBLIC key into src/license/keys.ts → EMBEDDED_PUBLIC_KEY_B64:\n");
console.log(Buffer.from(publicKey).toString("base64"));
