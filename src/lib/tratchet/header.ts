import { equalBytes, readU16, toHex, writeU16 } from "./bytes.ts";
import {
  HEADER_LEN,
  PROTOCOL_VERSION,
  SPQR_CHUNK,
  X25519_PK_LEN,
} from "./params.ts";
import type { SpqrSlot, SpqrType } from "./spqr.ts";

/**
 * Fixed 176-byte data header.
 *
 *  0   version u8
 *  1   flags u8
 *  2   n u16
 *  4   pn u16
 *  6   dh_pub 32
 * 38   install_epoch u8
 * 39   spqr_type u8
 * 40   spqr_epoch u16
 * 42   spqr_total u8
 * 43   spqr_idx0 u8
 * 44   spqr_idx1 u8
 * 45   chunk0 64
 * 109  chunk1 64
 * 173  pad 3
 */
export type DataHeader = {
  n: number;
  pn: number;
  dhPub: Uint8Array;
  installEpoch: number;
  slots: SpqrSlot[];
  raw: Uint8Array;
};

export function encodeHeader(h: {
  n: number;
  pn: number;
  dhPub: Uint8Array;
  installEpoch: number;
  slots: SpqrSlot[];
}): Uint8Array {
  if (h.dhPub.length !== X25519_PK_LEN) throw new Error("TR_HDR_DH");
  const raw = new Uint8Array(HEADER_LEN);
  raw[0] = PROTOCOL_VERSION;
  raw[1] = 0;
  writeU16(raw, 2, h.n);
  writeU16(raw, 4, h.pn);
  raw.set(h.dhPub, 6);
  raw[38] = h.installEpoch & 0xff;
  const s0 = h.slots[0];
  const s1 = h.slots[1];
  const type: SpqrType = s0?.type ?? 0;
  raw[39] = type;
  writeU16(raw, 40, s0?.epoch ?? 0);
  raw[42] = s0?.total ?? 0;
  raw[43] = s0 ? s0.idx : 0xff;
  raw[44] = s1 ? s1.idx : 0xff;
  if (s0) raw.set(s0.data, 45);
  if (s1) raw.set(s1.data, 109);
  return raw;
}

export function decodeHeader(raw: Uint8Array): DataHeader {
  if (raw.length !== HEADER_LEN) throw new Error("TR_HDR_LEN");
  if (raw[0] !== PROTOCOL_VERSION) throw new Error("TR_VERSION");
  const type = raw[39] as SpqrType;
  const epoch = readU16(raw, 40);
  const total = raw[42]!;
  const slots: SpqrSlot[] = [];
  const idx0 = raw[43]!;
  const idx1 = raw[44]!;
  if (type !== 0 && idx0 !== 0xff) {
    slots.push({
      epoch,
      type,
      total,
      idx: idx0,
      data: raw.subarray(45, 45 + SPQR_CHUNK),
    });
  }
  if (type !== 0 && idx1 !== 0xff) {
    slots.push({
      epoch,
      type,
      total,
      idx: idx1,
      data: raw.subarray(109, 109 + SPQR_CHUNK),
    });
  }
  return {
    n: readU16(raw, 2),
    pn: readU16(raw, 4),
    dhPub: raw.subarray(6, 38),
    installEpoch: raw[38]!,
    slots,
    raw,
  };
}

export function describeHeader(raw: Uint8Array): {
  n: number;
  pn: number;
  dhFp: string;
  installEpoch: number;
  spqrType: string;
  spqrEpoch: number;
  spqrIdx: string;
  spqrTotal: number;
} {
  const h = decodeHeader(raw);
  const typeName = ["none", "pk", "ct"][h.slots[0]?.type ?? 0] ?? "none";
  return {
    n: h.n,
    pn: h.pn,
    dhFp: toHex(h.dhPub.subarray(0, 4)),
    installEpoch: h.installEpoch,
    spqrType: typeName,
    spqrEpoch: h.slots[0]?.epoch ?? 0,
    spqrIdx: h.slots.map((s) => String(s.idx)).join(",") || "—",
    spqrTotal: h.slots[0]?.total ?? 0,
  };
}

export function sameDh(a: Uint8Array, b: Uint8Array | null): boolean {
  if (!b) return false;
  return equalBytes(a, b);
}
