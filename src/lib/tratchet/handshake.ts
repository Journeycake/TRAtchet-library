import { randomBytes } from "@noble/hashes/utils.js";
import { concat, equalBytes, utf8, zeroize } from "./bytes.ts";
import {
  identitySign,
  identityVerify,
  type IdentityKeyPair,
} from "./identity.ts";
import { hkdfSha256 } from "./kdf.ts";
import {
  ED25519_PK_LEN,
  ED25519_SIG_LEN,
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
  idLocal: Uint8Array;
  idPeer: Uint8Array;
};

export type HandshakePending = {
  sessionId: Uint8Array;
  nonce: Uint8Array;
  dh: DhKeyPair;
  kem: KemKeyPair;
  idPk: Uint8Array;
  peerPin: Uint8Array | null;
};

const BODY_INIT = 4 + 1 + SID_LEN + NONCE_LEN + X25519_PK_LEN + MLKEM_PK_LEN;
const BODY_RESP = 4 + 1 + SID_LEN + NONCE_LEN + X25519_PK_LEN + MLKEM_CT_LEN;
export const INIT_LEN = BODY_INIT + ED25519_PK_LEN + ED25519_SIG_LEN;
export const RESP_LEN = BODY_RESP + ED25519_PK_LEN + ED25519_SIG_LEN;

const OFF_SID = 5;
const OFF_NONCE = OFF_SID + SID_LEN;
const OFF_DH = OFF_NONCE + NONCE_LEN;
const OFF_KEM = OFF_DH + X25519_PK_LEN;
const OFF_ID_INIT = OFF_KEM + MLKEM_PK_LEN;
const OFF_SIG_INIT = OFF_ID_INIT + ED25519_PK_LEN;
const OFF_ID_RESP = OFF_KEM + MLKEM_CT_LEN;
const OFF_SIG_RESP = OFF_ID_RESP + ED25519_PK_LEN;

export function createInit(
  identity: IdentityKeyPair,
  peerPin: Uint8Array | null = null,
): { msg: Uint8Array; pending: HandshakePending } {
  const sessionId = randomBytes(SID_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const dh = dhKeygen();
  const kem = kemKeygen();
  const idPk = identity.publicKey;
  const transcript = initTranscript({
    sessionId,
    nonce,
    dhPk: dh.publicKey,
    kemPk: kem.publicKey,
    idPk,
  });
  const sig = identitySign(identity.secretKey, transcript);
  const msg = new Uint8Array(INIT_LEN);
  msg.set(MAGIC_INIT, 0);
  msg[4] = PROTOCOL_VERSION;
  msg.set(sessionId, OFF_SID);
  msg.set(nonce, OFF_NONCE);
  msg.set(dh.publicKey, OFF_DH);
  msg.set(kem.publicKey, OFF_KEM);
  msg.set(idPk, OFF_ID_INIT);
  msg.set(sig, OFF_SIG_INIT);
  return {
    msg,
    pending: {
      sessionId,
      nonce,
      dh,
      kem,
      idPk: idPk.slice(),
      peerPin: peerPin ? peerPin.slice() : null,
    },
  };
}

export function respondInit(
  initMsg: Uint8Array,
  identity: IdentityKeyPair,
  peerPin: Uint8Array | null = null,
): { msg: Uint8Array; secrets: HandshakeSecrets } {
  const parsed = parseInit(initMsg);
  const tInit = initTranscript({
    sessionId: parsed.sessionId,
    nonce: parsed.nonce,
    dhPk: parsed.dhPk,
    kemPk: parsed.kemPk,
    idPk: parsed.idPk,
  });
  if (!identityVerify(parsed.idPk, tInit, parsed.sig)) {
    throw new Error("TR_SIG");
  }
  checkPin(parsed.idPk, peerPin);

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
    parsed.idPk,
    identity.publicKey,
  );
  zeroize(dhSs, sharedSecret);

  const tResp = respTranscript({
    sessionId: parsed.sessionId,
    nonceI: parsed.nonce,
    nonceR: nonce,
    dhPkI: parsed.dhPk,
    dhPkR: dh.publicKey,
    kemPk: parsed.kemPk,
    kemCt: cipherText,
    idPkI: parsed.idPk,
    idPkR: identity.publicKey,
  });
  const sig = identitySign(identity.secretKey, tResp);

  const msg = new Uint8Array(RESP_LEN);
  msg.set(MAGIC_RESP, 0);
  msg[4] = PROTOCOL_VERSION;
  msg.set(parsed.sessionId, OFF_SID);
  msg.set(nonce, OFF_NONCE);
  msg.set(dh.publicKey, OFF_DH);
  msg.set(cipherText, OFF_KEM);
  msg.set(identity.publicKey, OFF_ID_RESP);
  msg.set(sig, OFF_SIG_RESP);
  return {
    msg,
    secrets: {
      role: "responder",
      sessionId: parsed.sessionId.slice(),
      dh,
      dhRemote: parsed.dhPk.slice(),
      idLocal: identity.publicKey.slice(),
      idPeer: parsed.idPk.slice(),
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
  const tResp = respTranscript({
    sessionId: pending.sessionId,
    nonceI: pending.nonce,
    nonceR: parsed.nonce,
    dhPkI: pending.dh.publicKey,
    dhPkR: parsed.dhPk,
    kemPk: pending.kem.publicKey,
    kemCt: parsed.ct,
    idPkI: pending.idPk,
    idPkR: parsed.idPk,
  });
  if (!identityVerify(parsed.idPk, tResp, parsed.sig)) {
    throw new Error("TR_SIG");
  }
  checkPin(parsed.idPk, pending.peerPin);

  const dhSs = dhShared(pending.dh.secretKey, parsed.dhPk);
  const kemSs = kemDecaps(pending.kem.secretKey, parsed.ct);
  const derived = deriveSecrets(
    pending.sessionId,
    pending.nonce,
    parsed.nonce,
    dhSs,
    kemSs,
    pending.idPk,
    parsed.idPk,
  );
  zeroize(dhSs, kemSs, pending.kem.secretKey);
  return {
    role: "initiator",
    sessionId: pending.sessionId,
    dh: pending.dh,
    dhRemote: parsed.dhPk.slice(),
    idLocal: pending.idPk.slice(),
    idPeer: parsed.idPk.slice(),
    ...derived,
  };
}

function deriveSecrets(
  sessionId: Uint8Array,
  nonceI: Uint8Array,
  nonceR: Uint8Array,
  dhSs: Uint8Array,
  kemSs: Uint8Array,
  idPkI: Uint8Array,
  idPkR: Uint8Array,
) {
  const salt = concat(nonceI, nonceR);
  const ikm = concat(dhSs, kemSs);
  const bound = concat(sessionId, idPkI, idPkR);
  const info = concat(utf8(INFO.root), bound);
  const material = hkdfSha256(ikm, salt, info, 96);
  const pqInfo = concat(utf8(INFO.pqRoot), bound);
  const pq = hkdfSha256(ikm, salt, pqInfo, 64);
  return {
    root: material.subarray(0, 32),
    ckInit: material.subarray(32, 64),
    ckResp: material.subarray(64, 96),
    pqInit: pq.subarray(0, 32),
    pqResp: pq.subarray(32, 64),
  };
}

function initTranscript(p: {
  sessionId: Uint8Array;
  nonce: Uint8Array;
  dhPk: Uint8Array;
  kemPk: Uint8Array;
  idPk: Uint8Array;
}): Uint8Array {
  return concat(
    utf8(INFO.hsInit),
    new Uint8Array([PROTOCOL_VERSION]),
    p.sessionId,
    p.nonce,
    p.dhPk,
    p.kemPk,
    p.idPk,
  );
}

function respTranscript(p: {
  sessionId: Uint8Array;
  nonceI: Uint8Array;
  nonceR: Uint8Array;
  dhPkI: Uint8Array;
  dhPkR: Uint8Array;
  kemPk: Uint8Array;
  kemCt: Uint8Array;
  idPkI: Uint8Array;
  idPkR: Uint8Array;
}): Uint8Array {
  return concat(
    utf8(INFO.hsResp),
    new Uint8Array([PROTOCOL_VERSION]),
    p.sessionId,
    p.nonceI,
    p.nonceR,
    p.dhPkI,
    p.dhPkR,
    p.kemPk,
    p.kemCt,
    p.idPkI,
    p.idPkR,
  );
}

function checkPin(got: Uint8Array, pin: Uint8Array | null | undefined): void {
  if (!pin) return;
  if (pin.length !== ED25519_PK_LEN || !equalBytes(got, pin)) {
    throw new Error("TR_IDENTITY");
  }
}

function parseInit(msg: Uint8Array) {
  if (msg.length !== INIT_LEN) throw new Error("TR_BAD_HANDSHAKE");
  if (!equalBytes(msg.subarray(0, 4), MAGIC_INIT)) throw new Error("TR_BAD_HANDSHAKE");
  if (msg[4] !== PROTOCOL_VERSION) throw new Error("TR_VERSION");
  return {
    sessionId: msg.subarray(OFF_SID, OFF_NONCE),
    nonce: msg.subarray(OFF_NONCE, OFF_DH),
    dhPk: msg.subarray(OFF_DH, OFF_KEM),
    kemPk: msg.subarray(OFF_KEM, OFF_ID_INIT),
    idPk: msg.subarray(OFF_ID_INIT, OFF_SIG_INIT),
    sig: msg.subarray(OFF_SIG_INIT, INIT_LEN),
  };
}

function parseResp(msg: Uint8Array) {
  if (msg.length !== RESP_LEN) throw new Error("TR_BAD_HANDSHAKE");
  if (!equalBytes(msg.subarray(0, 4), MAGIC_RESP)) throw new Error("TR_BAD_HANDSHAKE");
  if (msg[4] !== PROTOCOL_VERSION) throw new Error("TR_VERSION");
  return {
    sessionId: msg.subarray(OFF_SID, OFF_NONCE),
    nonce: msg.subarray(OFF_NONCE, OFF_DH),
    dhPk: msg.subarray(OFF_DH, OFF_KEM),
    ct: msg.subarray(OFF_KEM, OFF_ID_RESP),
    idPk: msg.subarray(OFF_ID_RESP, OFF_SIG_RESP),
    sig: msg.subarray(OFF_SIG_RESP, RESP_LEN),
  };
}

export function classifyHandshake(msg: Uint8Array): "init" | "resp" | "unknown" {
  if (msg.length >= 4 && equalBytes(msg.subarray(0, 4), MAGIC_INIT)) return "init";
  if (msg.length >= 4 && equalBytes(msg.subarray(0, 4), MAGIC_RESP)) return "resp";
  return "unknown";
}
