/** Locked v0.3 protocol parameters. */

export const PROTOCOL = "TRatchet";
export const PROTOCOL_VERSION = 1;
export const PROTOCOL_LABEL = "TRATCHET-v1";

export const MLKEM_PARAM = "ML-KEM-768" as const;
export const AEAD_NAME = "XChaCha20-Poly1305" as const;
export const CLASSICAL_DH = "X25519" as const;

export const X25519_PK_LEN = 32;
export const X25519_SK_LEN = 32;
export const MLKEM_PK_LEN = 1184;
export const MLKEM_SK_LEN = 2400;
export const MLKEM_CT_LEN = 1088;
export const MLKEM_SS_LEN = 32;
export const SID_LEN = 16;
export const NONCE_LEN = 32;
export const KEY_LEN = 32;
export const AEAD_NONCE_LEN = 24;
export const AEAD_TAG_LEN = 16;

export const HEADER_LEN = 176;
export const SPQR_CHUNK = 64;
export const SPQR_CHUNKS_PER_MSG = 2;
export const MAX_PLAINTEXT = 1100;
export const MAX_SKIP = 64;
export const MAX_SKIPPED_STORE = 128;
export const RECORD_LEN_SIZE = 4;
export const MAX_RECORD = 8192;

export const MAGIC_INIT = new Uint8Array([0x54, 0x52, 0x31, 0x49]); // TR1I
export const MAGIC_RESP = new Uint8Array([0x54, 0x52, 0x31, 0x52]); // TR1R

export const INFO = {
  root: "TRATCHET-v1",
  pqRoot: "TRATCHET-PQ-v1",
  rk: "TRATCHET-RK-v1",
  hybrid: "TRATCHET-HYBRID-MK-v1",
  pqEpoch: "TRATCHET-PQ-EPOCH-v1",
  pqInstall: "TRATCHET-PQ-INSTALL-v1",
} as const;
