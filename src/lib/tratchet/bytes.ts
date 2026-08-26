/** Byte helpers for TRatchet. No I/O. */

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function zeroize(...bufs: Array<Uint8Array | null | undefined>): void {
  for (const b of bufs) {
    if (b) b.fill(0);
  }
}

/** Length-constant compare; false if lengths differ. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(h: string): Uint8Array {
  const hex = h.replace(/^0x/i, "").replace(/\s+/g, "");
  if (hex.length % 2) throw new Error("TR_HEX_ODD");
  if (hex.length > 0 && !/^[0-9a-fA-F]+$/.test(hex)) throw new Error("TR_HEX");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** First 8 bytes of SHA-256, hex — safe to display. */
export function fingerprint(b: Uint8Array): string {
  return toHex(sha256sync(b).subarray(0, 8));
}

export function view(buf: Uint8Array): DataView {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function readU16(buf: Uint8Array, offset: number): number {
  return view(buf).getUint16(offset, false);
}

export function readU32(buf: Uint8Array, offset: number): number {
  return view(buf).getUint32(offset, false);
}

export function writeU16(buf: Uint8Array, offset: number, n: number): void {
  view(buf).setUint16(offset, n, false);
}

export function writeU32(buf: Uint8Array, offset: number, n: number): void {
  view(buf).setUint32(offset, n, false);
}

import { sha256 } from "@noble/hashes/sha2.js";

function sha256sync(b: Uint8Array): Uint8Array {
  return sha256(b);
}

export { sha256 };
