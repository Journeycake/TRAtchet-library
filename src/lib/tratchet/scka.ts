/**
 * Thin ML-KEM-768 SCKA provider (spec §6, Option 1).
 * Primitive: @noble/post-quantum (FIPS 203). Chunking lives in spqr.ts.
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { MLKEM_CT_LEN, MLKEM_PK_LEN, MLKEM_SK_LEN, MLKEM_SS_LEN } from "./params.ts";
import { zeroize } from "./bytes.ts";

export type KemKeyPair = { secretKey: Uint8Array; publicKey: Uint8Array };

export function kemKeygen(): KemKeyPair {
  const kp = ml_kem768.keygen();
  if (kp.publicKey.length !== MLKEM_PK_LEN) throw new Error("TR_KEM_PK");
  if (kp.secretKey.length !== MLKEM_SK_LEN) throw new Error("TR_KEM_SK");
  return kp;
}

export function kemEncaps(publicKey: Uint8Array): {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
} {
  if (publicKey.length !== MLKEM_PK_LEN) throw new Error("TR_KEM_PK");
  const out = ml_kem768.encapsulate(publicKey);
  if (out.cipherText.length !== MLKEM_CT_LEN) throw new Error("TR_KEM_CT");
  if (out.sharedSecret.length !== MLKEM_SS_LEN) throw new Error("TR_KEM_SS");
  return out;
}

export function kemDecaps(secretKey: Uint8Array, cipherText: Uint8Array): Uint8Array {
  if (secretKey.length !== MLKEM_SK_LEN) throw new Error("TR_KEM_SK");
  if (cipherText.length !== MLKEM_CT_LEN) throw new Error("TR_KEM_CT");
  const ss = ml_kem768.decapsulate(cipherText, secretKey);
  if (ss.length !== MLKEM_SS_LEN) throw new Error("TR_KEM_SS");
  return ss;
}

export function kemZeroize(kp: KemKeyPair | null): void {
  if (!kp) return;
  zeroize(kp.secretKey, kp.publicKey);
}
