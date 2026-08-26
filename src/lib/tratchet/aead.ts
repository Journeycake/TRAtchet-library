import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { AEAD_NONCE_LEN, KEY_LEN } from "./params.ts";

export function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_LEN) throw new Error("TR_AEAD_KEY");
  if (nonce.length !== AEAD_NONCE_LEN) throw new Error("TR_AEAD_NONCE");
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

export function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_LEN) throw new Error("TR_AEAD_KEY");
  if (nonce.length !== AEAD_NONCE_LEN) throw new Error("TR_AEAD_NONCE");
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new Error("TR_DECRYPT_FAIL");
  }
}
