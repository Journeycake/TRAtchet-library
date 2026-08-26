import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { fingerprint } from "./bytes.ts";
import { INIT_LEN, RESP_LEN } from "./handshake.ts";
import { identityKeygen, identitySign, identityVerify } from "./identity.ts";
import { ED25519_PK_LEN, ED25519_SIG_LEN } from "./params.ts";
import { Session } from "./session.ts";

function pinnedPair() {
  const idA = identityKeygen();
  const idB = identityKeygen();
  const a = new Session({ identity: idA, peerIdentity: idB.publicKey });
  const b = new Session({ identity: idB, peerIdentity: idA.publicKey });
  const init = a.handshakeInit();
  const resp = b.handshakeRespond(init);
  a.handshakeFinish(resp);
  return { a, b, idA, idB };
}

describe("Ed25519 handshake signatures", () => {
  it("round-trips Ed25519 sign/verify", () => {
    const kp = identityKeygen();
    assert.equal(kp.publicKey.length, ED25519_PK_LEN);
    const msg = new Uint8Array([1, 2, 3, 4]);
    const sig = identitySign(kp.secretKey, msg);
    assert.equal(sig.length, ED25519_SIG_LEN);
    assert.equal(identityVerify(kp.publicKey, msg, sig), true);
    sig[0] ^= 1;
    assert.equal(identityVerify(kp.publicKey, msg, sig), false);
  });

  it("uses fixed v2 handshake sizes including identity and signature", () => {
    const a = new Session();
    const b = new Session();
    const init = a.handshakeInit();
    assert.equal(init.length, INIT_LEN);
    const resp = b.handshakeRespond(init);
    assert.equal(resp.length, RESP_LEN);
  });

  it("pins peer identities and records them on the session", () => {
    const { a, b, idA, idB } = pinnedPair();
    assert.equal(a.snapshot().idFp, fingerprint(idA.publicKey));
    assert.equal(a.snapshot().peerIdFp, fingerprint(idB.publicKey));
    assert.equal(b.snapshot().peerIdFp, fingerprint(idA.publicKey));
    assert.equal(a.snapshot().idPinned, true);
    const sealed = a.encryptText("pinned-ok");
    assert.equal(b.decryptText(sealed.header, sealed.ciphertext), "pinned-ok");
  });

  it("rejects a responder identity that does not match the initiator pin", () => {
    const idA = identityKeygen();
    const idB = identityKeygen();
    const idM = identityKeygen();
    const a = new Session({ identity: idA, peerIdentity: idB.publicKey });
    const m = new Session({ identity: idM });
    const init = a.handshakeInit();
    const resp = m.handshakeRespond(init);
    assert.throws(() => a.handshakeFinish(resp), /TR_IDENTITY/);
  });

  it("rejects an initiator identity that does not match the responder pin", () => {
    const idA = identityKeygen();
    const idB = identityKeygen();
    const idM = identityKeygen();
    const m = new Session({ identity: idM });
    const b = new Session({ identity: idB, peerIdentity: idA.publicKey });
    const init = m.handshakeInit();
    assert.throws(() => b.handshakeRespond(init), /TR_IDENTITY/);
  });

  it("rejects a flipped bit in the initiator signature", () => {
    const a = new Session();
    const b = new Session();
    const init = a.handshakeInit();
    init[init.length - 1] ^= 1;
    assert.throws(() => b.handshakeRespond(init), /TR_SIG/);
  });

  it("rejects a flipped DH public key in the responder flight", () => {
    const a = new Session();
    const b = new Session();
    const init = a.handshakeInit();
    const resp = b.handshakeRespond(init);
    resp[53] ^= 1;
    assert.throws(() => a.handshakeFinish(resp), /TR_SIG/);
  });

  it("rejects a relayed response from a split MITM session", () => {
    const idA = identityKeygen();
    const idB = identityKeygen();
    const idM = identityKeygen();
    const a = new Session({ identity: idA, peerIdentity: idB.publicKey });
    const b = new Session({ identity: idB });
    const m = new Session({ identity: idM });
    a.handshakeInit();
    const initM = m.handshakeInit();
    const respB = b.handshakeRespond(initM);
    assert.throws(() => a.handshakeFinish(respB), /TR_SID_MISMATCH|TR_SIG|TR_IDENTITY/);
  });

  it("without a pin, a different identity still completes (TOFU)", () => {
    const a = new Session();
    const m = new Session();
    const init = a.handshakeInit();
    const resp = m.handshakeRespond(init);
    a.handshakeFinish(resp);
    assert.equal(a.phase, "established");
    assert.equal(a.snapshot().idPinned, false);
    assert.equal(a.snapshot().peerIdFp, fingerprint(m.identityPublic));
  });
});
