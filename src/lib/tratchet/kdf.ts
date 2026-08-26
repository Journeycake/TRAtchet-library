import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concat, utf8, zeroize } from "./bytes.ts";
import { INFO, KEY_LEN } from "./params.ts";

export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: string | Uint8Array,
  length: number,
): Uint8Array {
  const infoBytes = typeof info === "string" ? utf8(info) : info;
  return hkdf(sha256, ikm, salt, infoBytes, length);
}

/** Signal-style chain KDF: MK = HMAC(ck, 0x01), CK' = HMAC(ck, 0x02). */
export function kdfCk(ck: Uint8Array): { ck: Uint8Array; mk: Uint8Array } {
  const mk = hmac(sha256, ck, new Uint8Array([0x01]));
  const next = hmac(sha256, ck, new Uint8Array([0x02]));
  return { ck: next, mk };
}

/** Root KDF: HKDF(RK || DH) → RK' || CK. */
export function kdfRk(
  rk: Uint8Array,
  dhOut: Uint8Array,
): { rk: Uint8Array; ck: Uint8Array } {
  const okm = hkdfSha256(concat(rk, dhOut), undefined, INFO.rk, 64);
  return { rk: okm.subarray(0, KEY_LEN), ck: okm.subarray(KEY_LEN, 64) };
}

/**
 * Hybrid message key. Breaking only X25519 or only ML-KEM is not enough:
 * IKM is the concatenation of both contributions.
 */
export function kdfHybrid(
  ecMk: Uint8Array,
  pqMk: Uint8Array,
): { key: Uint8Array; nonce: Uint8Array } {
  const okm = hkdfSha256(concat(ecMk, pqMk), undefined, INFO.hybrid, 56);
  return { key: okm.subarray(0, KEY_LEN), nonce: okm.subarray(KEY_LEN, 56) };
}

export function mixPq(ck: Uint8Array, ss: Uint8Array): Uint8Array {
  const next = hkdfSha256(concat(ck, ss), undefined, INFO.pqInstall, KEY_LEN);
  zeroize(ck);
  return next;
}

export function kdfInstallMk(pqMk: Uint8Array, ss: Uint8Array): Uint8Array {
  return hkdfSha256(concat(pqMk, ss), undefined, INFO.pqEpoch, KEY_LEN);
}
