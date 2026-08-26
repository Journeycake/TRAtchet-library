/** Long-term Ed25519 identity keys. Sign handshake transcripts; never used as DH. */
import { ed25519 } from "@noble/curves/ed25519.js";
import { ED25519_PK_LEN, ED25519_SIG_LEN, ED25519_SK_LEN } from "./params.ts";

export type IdentityKeyPair = { secretKey: Uint8Array; publicKey: Uint8Array };

export function identityKeygen(): IdentityKeyPair {
  const kp = ed25519.keygen();
  if (kp.publicKey.length !== ED25519_PK_LEN) throw new Error("TR_ID_PK");
  if (kp.secretKey.length !== ED25519_SK_LEN) throw new Error("TR_ID_SK");
  return kp;
}

export function identityFromSeed(seed: Uint8Array): IdentityKeyPair {
  if (seed.length !== ED25519_SK_LEN) throw new Error("TR_ID_SK");
  const kp = ed25519.keygen(seed.slice());
  if (kp.publicKey.length !== ED25519_PK_LEN) throw new Error("TR_ID_PK");
  if (kp.secretKey.length !== ED25519_SK_LEN) throw new Error("TR_ID_SK");
  return kp;
}

export function identityPublic(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== ED25519_SK_LEN) throw new Error("TR_ID_SK");
  return ed25519.getPublicKey(secretKey);
}

export function identitySign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (secretKey.length !== ED25519_SK_LEN) throw new Error("TR_ID_SK");
  const sig = ed25519.sign(message, secretKey);
  if (sig.length !== ED25519_SIG_LEN) throw new Error("TR_ID_SIG");
  return sig;
}

/** RFC 8032 verification (canonical, not ZIP-215). */
export function identityVerify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PK_LEN) return false;
  if (signature.length !== ED25519_SIG_LEN) return false;
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
