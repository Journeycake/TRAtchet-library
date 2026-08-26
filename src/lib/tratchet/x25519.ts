import { x25519 } from "@noble/curves/ed25519.js";
import { X25519_PK_LEN, X25519_SK_LEN } from "./params.ts";

export type DhKeyPair = { secretKey: Uint8Array; publicKey: Uint8Array };

export function dhKeygen(): DhKeyPair {
  return x25519.keygen();
}

export function dhPublic(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== X25519_SK_LEN) throw new Error("TR_DH_SK");
  return x25519.getPublicKey(secretKey);
}

export function dhShared(secretKey: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  if (secretKey.length !== X25519_SK_LEN) throw new Error("TR_DH_SK");
  if (peerPublic.length !== X25519_PK_LEN) throw new Error("TR_DH_PK");
  return x25519.getSharedSecret(secretKey, peerPublic);
}
