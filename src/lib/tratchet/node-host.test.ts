import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  classifyRecord,
  encodeRecord,
  RecordParser,
  splitDataRecord,
} from "./framing.ts";
import { HEADER_LEN, RECORD_LEN_SIZE } from "./params.ts";
import { runHostPair } from "./node-host.ts";
import { Session } from "./session.ts";

describe("stream framing", () => {
  it("round-trips a payload across chunked reads", () => {
    const payload = new Uint8Array(17).map((_, i) => i + 1);
    const framed = encodeRecord(payload);
    assert.equal(framed.length, RECORD_LEN_SIZE + payload.length);
    const parser = new RecordParser();
    const a = parser.push(framed.subarray(0, 3));
    const b = parser.push(framed.subarray(3));
    assert.equal(a.length, 0);
    assert.equal(b.length, 1);
    assert.deepEqual(Array.from(b[0]!), Array.from(payload));
  });

  it("classifies handshake vs data records", () => {
    const a = new Session();
    const b = new Session();
    const init = a.handshakeInit();
    assert.equal(classifyRecord(init), "init");
    const resp = b.handshakeRespond(init);
    assert.equal(classifyRecord(resp), "resp");
    a.handshakeFinish(resp);
    const sealed = a.encryptText("hi");
    const rec = new Uint8Array(sealed.header.length + sealed.ciphertext.length);
    rec.set(sealed.header, 0);
    rec.set(sealed.ciphertext, sealed.header.length);
    assert.equal(classifyRecord(rec), "data");
    const split = splitDataRecord(rec);
    assert.equal(split.header.length, HEADER_LEN);
    a.free();
    b.free();
  });
});

describe("Node host pair", () => {
  it("handshakes and ping-pongs over TCP", async () => {
    const result = await runHostPair({ transport: "tcp", flushEpoch: false });
    assert.equal(result.transport, "tcp");
    assert.match(result.bind, /^tcp \d+$/);
    assert.equal(result.alpha.ns, 1);
    assert.equal(result.bravo.ns, 1);
    assert.equal(result.alpha.nr, 1);
    assert.equal(result.bravo.nr, 1);
    const texts = result.events.filter((e) => e.kind === "data").map((e) => e.text);
    assert.deepEqual(texts, [
      "session-layer up from alpha",
      "ack from bravo",
      "linux-to-linux over the same library",
    ]);
    assert.equal(result.events.filter((e) => e.kind === "control").length, 0);
    assert.ok(result.bytesOnWire > 2000);
  });

  it("handshakes over a Unix socket and can finish a PQ epoch", async () => {
    const result = await runHostPair({ transport: "unix", flushEpoch: true });
    assert.equal(result.transport, "unix");
    assert.match(result.bind, /^unix /);
    assert.ok(result.events.some((e) => e.kind === "control"));
    const lastApp = result.events.filter((e) => e.kind === "data").at(-1);
    assert.equal(lastApp?.text, "pq epoch mixed into both chains");
    assert.ok(result.alpha.pqEpoch >= 1);
  });
});
