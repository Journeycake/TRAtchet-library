/** Length-prefixed records for stream transports (TCP, Unix sockets). No I/O. */

import { classifyHandshake } from "./handshake.ts";
import { AEAD_TAG_LEN, HEADER_LEN, MAX_RECORD, RECORD_LEN_SIZE } from "./params.ts";
import { concat, readU32, writeU32 } from "./bytes.ts";

export function encodeRecord(payload: Uint8Array): Uint8Array {
  if (payload.length === 0 || payload.length > MAX_RECORD) {
    throw new Error("TR_RECORD_SIZE");
  }
  const out = new Uint8Array(RECORD_LEN_SIZE + payload.length);
  writeU32(out, 0, payload.length);
  out.set(payload, RECORD_LEN_SIZE);
  return out;
}

export function encodeDataRecord(header: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (header.length !== HEADER_LEN) throw new Error("TR_HDR_LEN");
  return encodeRecord(concat(header, ciphertext));
}

export type RecordKind = "init" | "resp" | "data";

export function classifyRecord(payload: Uint8Array): RecordKind {
  const hs = classifyHandshake(payload);
  if (hs === "init" || hs === "resp") return hs;
  if (payload.length < HEADER_LEN + AEAD_TAG_LEN) throw new Error("TR_RECORD_SHORT");
  return "data";
}

export function splitDataRecord(payload: Uint8Array): {
  header: Uint8Array;
  ciphertext: Uint8Array;
} {
  if (classifyRecord(payload) !== "data") throw new Error("TR_NOT_DATA");
  return {
    header: payload.subarray(0, HEADER_LEN),
    ciphertext: payload.subarray(HEADER_LEN),
  };
}

export class RecordParser {
  private buf: Uint8Array = new Uint8Array(0);

  push(chunk: Uint8Array): Uint8Array[] {
    this.buf = concat(this.buf, chunk);
    const out: Uint8Array[] = [];
    while (this.buf.length >= RECORD_LEN_SIZE) {
      const len = readU32(this.buf, 0);
      if (len === 0 || len > MAX_RECORD) throw new Error("TR_RECORD_SIZE");
      if (this.buf.length < RECORD_LEN_SIZE + len) break;
      out.push(this.buf.subarray(RECORD_LEN_SIZE, RECORD_LEN_SIZE + len));
      this.buf = this.buf.subarray(RECORD_LEN_SIZE + len);
    }
    return out;
  }
}
