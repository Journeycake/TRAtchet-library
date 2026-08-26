import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Session } from "./session.ts";
import { fingerprint, utf8 } from "./bytes.ts";
import { reconstruct, chunkify } from "./spqr.ts";
import { HEADER_LEN, MAX_PLAINTEXT } from "./params.ts";

function pair() {
  const a = new Session();
  const b = new Session();
  const init = a.handshakeInit();
  const resp = b.handshakeRespond(init);
  a.handshakeFinish(resp);
  return { a, b };
}

describe("TRatchet handshake + triple ratchet", () => {
  it("completes online PQXDH and round-trips a message", () => {
    const { a, b } = pair();
    assert.equal(a.phase, "established");
    assert.equal(b.phase, "established");
    assert.equal(a.snapshot().sessionId, b.snapshot().sessionId);
    const sealed = a.encryptText("alpha-hello");
    assert.equal(sealed.header.length, HEADER_LEN);
    const pt = b.decryptText(sealed.header, sealed.ciphertext);
    assert.equal(pt, "alpha-hello");
  });

  it("supports either side sending first", () => {
    const { a, b } = pair();
    const sealed = b.encryptText("bravo-first");
    assert.equal(a.decryptText(sealed.header, sealed.ciphertext), "bravo-first");
  });

  it("ratchets so each message has a unique hybrid key", () => {
    const { a, b } = pair();
    const fps = new Set<string>();
    for (let i = 0; i < 4; i++) {
      const s = a.encryptText(`m${i}`);
      b.decrypt(s.header, s.ciphertext);
      fps.add(a.lastHybridFp);
      fps.add(b.lastHybridFp);
      assert.equal(a.lastHybridFp, b.lastHybridFp);
    }
    assert.equal(fps.size, 4);
  });

  it("ping-pongs and DH-ratchets on direction change", () => {
    const { a, b } = pair();
    const s1 = a.encryptText("one");
    assert.equal(b.decryptText(s1.header, s1.ciphertext), "one");
    const s2 = b.encryptText("two");
    assert.equal(a.decryptText(s2.header, s2.ciphertext), "two");
    assert.equal(a.lastTrace?.dhRatchet, true);
    const s3 = a.encryptText("three");
    assert.equal(b.decryptText(s3.header, s3.ciphertext), "three");
    assert.equal(b.lastTrace?.dhRatchet, true);
  });

  it("decrypts two in-flight messages out of order", () => {
    const { a, b } = pair();
    const m0 = a.encryptText("first");
    const m1 = a.encryptText("second");
    assert.equal(b.decryptText(m1.header, m1.ciphertext), "second");
    assert.equal(b.decryptText(m0.header, m0.ciphertext), "first");
  });

  it("rejects oversized plaintext", () => {
    const { a } = pair();
    assert.throws(
      () => a.encrypt(new Uint8Array(MAX_PLAINTEXT + 1)),
      /TR_PLAINTEXT_TOO_LARGE/,
    );
  });

  it("exports and imports session state", () => {
    const { a, b } = pair();
    const s = a.encryptText("keep");
    b.decrypt(s.header, s.ciphertext);
    const blob = a.exportState();
    const c = new Session();
    c.importState(blob);
    const s2 = c.encryptText("after-import");
    assert.equal(b.decryptText(s2.header, s2.ciphertext), "after-import");
  });

  it("completes a sparse PQ epoch across chunked messages", () => {
    const { a, b } = pair();
    let i = 0;
    while (a.remainingPqChunks() > 0 && i++ < 50) {
      const s = a.encryptText(`pk-${i}`);
      b.decrypt(s.header, s.ciphertext);
    }
    assert.equal(a.remainingPqChunks(), 0);
    i = 0;
    while (b.remainingPqChunks() > 0 && i++ < 50) {
      const s = b.encryptText(`ct-${i}`);
      a.decrypt(s.header, s.ciphertext);
    }
    assert.equal(b.remainingPqChunks(), 0);
    const before = a.snapshot().pqSendFp;
    const ack = a.encryptText("install");
    b.decrypt(ack.header, ack.ciphertext);
    assert.equal(a.snapshot().pq?.lastInstalled, 1);
    const after = a.snapshot().pqSendFp;
    assert.notEqual(before, after);
    const reply = b.encryptText("healed");
    assert.equal(a.decryptText(reply.header, reply.ciphertext), "healed");
  });

  it("zeroizes on free", () => {
    const { a } = pair();
    a.free();
    assert.equal(a.phase, "closed");
    assert.throws(() => a.encryptText("nope"), /TR_NOT_ESTABLISHED|TR_PHASE/);
  });
});

describe("SPQR chunking", () => {
  it("reconstructs with all chunks", () => {
    const data = utf8("ml-kem-public-key-material-example-bytes-for-spqr");
    const chunks = chunkify(data);
    const map = new Map(chunks.map((c, i) => [i, c]));
    const out = reconstruct(map, chunks.length);
    assert.ok(out);
    assert.equal(Buffer.from(out!).toString(), Buffer.from(data).toString());
  });

  it("recovers a single missing data chunk via parity", () => {
    const data = new Uint8Array(200).map((_, i) => i & 0xff);
    const chunks = chunkify(data);
    const map = new Map(chunks.map((c, i) => [i, c]));
    map.delete(2);
    const out = reconstruct(map, chunks.length);
    assert.ok(out);
    assert.equal(fingerprint(out!), fingerprint(data));
  });
});
