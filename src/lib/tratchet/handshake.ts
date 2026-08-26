import { randomBytes } from "@noble/hashes/utils.js";
import { concat, equalBytes, utf8, zeroize } from "./bytes.ts";
import { hkdfSha256 } from "./kdf.ts";
import {
  INFO,
  MAGIC_INIT,
  MAGIC_RESP,
  MLKEM_CT_LEN,
  MLKEM_PK_LEN,
  NONCE_LEN,
  PROTOCOL_VERSION,
  SID_LEN,
  X25519_PK_LEN,
} from "./params.ts";
import { kemDecaps, kemEncaps, kemKeygen, type KemKeyPair } from "./scka.ts";
import { dhKeygen, dhShared, type DhKeyPair } from "./x25519.ts";

export type Role = "initiator" | "responder";

export type HandshakeSecrets = {
  role: Role;
  sessionId: Uint8Array;
  root: Uint8Array;
  ckInit: Uint8Array;
  ckResp: Uint8Array;
  pqInit: Uint8Array;
  pqResp: Uint8Array;
  dh: DhKeyPair;
  dhRemote: Uint8Array;
};

export type HandshakePending = {
  sessionId: Uint8Array;
  nonce: Uint8Array;
  dh: DhKeyPair;
  kem: KemKeyPair;
};

const INIT_LEN = 4 + 1 + SID_LEN + NONCE_LEN + X25519_PK_LEN + MLKEM_PK_LEN;
const RESP_LEN = 4 + 1 + SID_LEN + NONCE_LEN + X25519_PK_LEN + MLKEM_CT_LEN;

export function createInit(): { msg: Uint8Array; pending: HandshakePending } {
  const sessionId = randomBytes(SID_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const dh = dhKeygen();
  const kem = kemKeygen();
  const msg = new Uint8Array(INIT_LEN);
  msg.set(MAGIC_INIT, 0);
  msg[4] = PROTOCOL_VERSION;
  msg.set(sessionId, 5);
  msg.set(nonce, 5 + SID_LEN);
  msg.set(dh.publicKey, 5 + SID_LEN + NONCE_LEN);
  msg.set(kem.publicKey, 5 + SID_LEN + NONCE_LEN + X25519_PK_LEN);
  return { msg, pending: { sessionId, nonce, dh, kem } };
}

export function respondInit(initMsg: Uint8Array): {
  msg: Uint8Array;
  secrets: HandshakeSecrets;
} {
  const parsed = parseInit(initMsg);
  const nonce = randomBytes(NONCE_LEN);
  const dh = dhKeygen();
  const { cipherText, sharedSecret } = kemEncaps(parsed.kemPk);
  const dhSs = dhShared(dh.secretKey, parsed.dhPk);
  const derived = deriveSecrets(
    parsed.sessionId,
    parsed.nonce,
    nonce,
    dhSs,
    sharedSecret,
  );
  zeroize(dhSs, sharedSecret);
  const msg = new Uint8Array(RESP_LEN);
  msg.set(MAGIC_RESP, 0);
  msg[4] = PROTOCOL_VERSION;
  msg.set(parsed.sessionId, 5);
  msg.set(nonce, 5 + SID_LEN);
  msg.set(dh.publicKey, 5 + SID_LEN + NONCE_LEN);
  msg.set(cipherText, 5 + SID_LEN + NONCE_LEN + X25519_PK_LEN);
  return {
    msg,
    secrets: {
      role: "responder",
      sessionId: parsed.sessionId,
      dh,
      dhRemote: parsed.dhPk,
      ...derived,
    },
  };
}

export function finishHandshake(
  respMsg: Uint8Array,
  pending: HandshakePending,
): HandshakeSecrets {
  const parsed = parseResp(respMsg);
  if (!equalBytes(parsed.sessionId, pending.sessionId)) {
    throw new Error("TR_SID_MISMATCH");
  }
  const dhSs = dhShared(pending.dh.secretKey, parsed.dhPk);
  const kemSs = kemDecaps(pending.kem.secretKey, parsed.ct);
  const derived = deriveSecrets(
    pending.sessionId,
    pending.nonce,
    parsed.nonce,
    dhSs,
    kemSs,
  );
  zeroize(dhSs, kemSs, pending.kem.secretKey);
  return {
    role: "initiator",
    sessionId: pending.sessionId,
    dh: pending.dh,
    dhRemote: parsed.dhPk,
    ...derived,
  };
}

function deriveSecrets(
  sessionId: Uint8Array,
  nonceI: Uint8Array,
  nonceR: Uint8Array,
  dhSs: Uint8Array,
  kemSs: Uint8Array,
) {
  const salt = concat(nonceI, nonceR);
  const ikm = concat(dhSs, kemSs);
  const info = concat(utf8(INFO.root), sessionId);
  const material = hkdfSha256(ikm, salt, info, 96);
  const pqInfo = concat(utf8(INFO.pqRoot), sessionId);
  const pq = hkdfSha256(ikm, salt, pqInfo, 64);
  return {
    root: material.subarray(0, 32),
    ckInit: material.subarray(32, 64),
    ckResp: material.subarray(64, 96),
    pqInit: pq.subarray(0, 32),
    pqResp: pq.subarray(32, 64),
  };
}

function parseInit(msg: Uint8Array) {
  if (msg.length !== INIT_LEN) throw new Error("TR_BAD_HANDSHAKE");
  if (!equalBytes(msg.subarray(0, 4), MAGIC_INIT)) throw new Error("TR_BAD_HANDSHAKE");
  if (msg[4] !== PROTOCOL_VERSION) throw new Error("TR_VERSION");
  return {
    sessionId: msg.subarray(5, 5 + SID_LEN),
    nonce: msg.subarray(5 + SID_LEN, 5 + SID_LEN + NONCE_LEN),
    dhPk: msg.subarray(
      5 + SID_LEN + NONCE_LEN,
      5 + SID_LEN + NONCE_LEN + X25519_PK_LEN,
    ),
    kemPk: msg.subarray(5 + SID_LEN + NONCE_LEN + X25519_PK_LEN),
  };
}

function parseResp(msg: Uint8Array) {
  if (msg.length !== RESP_LEN) throw new Error("TR_BAD_HANDSHAKE");
  if (!equalBytes(msg.subarray(0, 4), MAGIC_RESP)) throw new Error("TR_BAD_HANDSHAKE");
  if (msg[4] !== PROTOCOL_VERSION) throw new Error("TR_VERSION");
  return {
    sessionId: msg.subarray(5, 5 + SID_LEN),
    nonce: msg.subarray(5 + SID_LEN, 5 + SID_LEN + NONCE_LEN),
    dhPk: msg.subarray(
      5 + SID_LEN + NONCE_LEN,
      5 + SID_LEN + NONCE_LEN + X25519_PK_LEN,
    ),
    ct: msg.subarray(5 + SID_LEN + NONCE_LEN + X25519_PK_LEN),
  };
}

export function classifyHandshake(msg: Uint8Array): "init" | "resp" | "unknown" {
  if (msg.length >= 4 && equalBytes(msg.subarray(0, 4), MAGIC_INIT)) return "init";
  if (msg.length >= 4 && equalBytes(msg.subarray(0, 4), MAGIC_RESP)) return "resp";
  return "unknown";
}
