// Internal service-to-service messaging — signs envelopes between microservices.
import nacl from "tweetnacl";

export function envelopeKeypair() {
  // ed25519 signs inter-service event envelopes on the message bus.
  return nacl.sign.keyPair();
}

export const TRANSPORT_CURVE = "x25519"; // key exchange for the gossip layer
export const SESSION_KEYSIZE = 256; // AES session key bits
