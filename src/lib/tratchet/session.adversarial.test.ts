import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { randomBytes } from "@noble/hashes/utils.js";
import { Session } from "./session.ts";
import { fromHex } from "./bytes.ts";
import { dhKeygen, dhShared } from "./x25519.ts";
import { HEADER_LEN } from "./params.ts";

function pair() {
  const a = new Session();
  const b = new Session();
  const init = a.handshakeInit();
  const resp = b.handshakeRespond(init);
  a.handshakeFinish(resp);
  return { a, b };
}

function flip(ct: Uint8Array): Uint8Array {
  const bad = ct.slice();
  bad[0] = (bad[0]! ^ 1) & 0xff;
  return bad;
}

describe("adversarial decrypt", () => {
  it("does not consume a chain step on AEAD failure — retry of the same record works", () => {
    const { a, b } = pair();
    const s = a.encryptText("retry-me");
    assert.throws(() => b.decrypt(s.header, flip(s.ciphertext)), /TR_DECRYPT_FAIL/);
    assert.equal(b.decryptText(s.header, s.ciphertext), "retry-me");
  });

  it("rejects replay of a delivered message without desyncing the next one", () => {
    const { a, b } = pair();
    const s0 = a.encryptText("one");
    assert.equal(b.decryptText(s0.header, s0.ciphertext), "one");
    assert.throws(() => b.decrypt(s0.header, s0.ciphertext), /TR_REPLAY/);
    const s1 = a.encryptText("two");
    assert.equal(b.decryptText(s1.header, s1.ciphertext), "two");
  });

  it("rolls back a forged DH public key so the real record still decrypts", () => {
    const { a, b } = pair();
    const forged = a.encryptText("real");
    const header = forged.header.slice();
    header.set(randomBytes(32), 6);
    assert.equal(header.length, HEADER_LEN);
    assert.throws(() => b.decrypt(header, forged.ciphertext), /TR_DECRYPT_FAIL|TR_DH_WEAK/);
    assert.equal(b.decryptText(forged.header, forged.ciphertext), "real");
  });

  it("keeps a skipped-message key if AEAD fails on the out-of-order record", () => {
    const { a, b } = pair();
    const m0 = a.encryptText("first");
    const m1 = a.encryptText("second");
    assert.equal(b.decryptText(m1.header, m1.ciphertext), "second");
    assert.throws(() => b.decrypt(m0.header, flip(m0.ciphertext)), /TR_DECRYPT_FAIL/);
    assert.equal(b.decryptText(m0.header, m0.ciphertext), "first");
  });
});

describe("primitive guards", () => {
  it("rejects a non-contributory (all-zero) X25519 public key", () => {
    const kp = dhKeygen();
    assert.throws(() => dhShared(kp.secretKey, new Uint8Array(32)), /TR_DH_WEAK/);
  });

  it("rejects non-hex in fromHex", () => {
    assert.throws(() => fromHex("zz"), /TR_HEX/);
  });
});
