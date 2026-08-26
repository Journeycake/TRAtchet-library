/**
 * Sparse Post-Quantum Ratchet: ML-KEM material is chunked with a single
 * XOR parity so any 1 lost chunk can be recovered (spec §6.2).
 */
import { concat, readU32, writeU32, zeroize } from "./bytes.ts";
import { kemDecaps, kemEncaps, kemKeygen } from "./scka.ts";
import { mixPq } from "./kdf.ts";
import { SPQR_CHUNK, SPQR_CHUNKS_PER_MSG } from "./params.ts";
import type { Role } from "./handshake.ts";

export type SpqrType = 0 | 1 | 2; // none | pk | ct

export type SpqrSlot = {
  epoch: number;
  type: SpqrType;
  total: number;
  idx: number;
  data: Uint8Array;
};

export type SpqrView = {
  epoch: number;
  role: "offeror" | "encapsulator";
  phase: "offer" | "wait-ct" | "send-ct" | "wait-install" | "idle";
  chunksSent: number;
  chunksRecv: number;
  chunksTotal: number;
  installPending: boolean;
  lastInstalled: number;
};

export class SparseRatchet {
  role: Role;
  epoch = 1;
  recv = new Map<number, Uint8Array>();
  recvTotal = 0;
  recvType: SpqrType = 0;
  recvEpoch = 0;
  offerChunks: Uint8Array[] | null = null;
  offerSk: Uint8Array | null = null;
  sendCursor = 0;
  ctChunks: Uint8Array[] | null = null;
  ctCursor = 0;
  pendingSs: Uint8Array | null = null;
  installPending = false;
  lastInstalled = 0;
  phase: SpqrView["phase"] = "idle";
  pqSend: Uint8Array;
  pqRecv: Uint8Array;

  constructor(role: Role, pqSend: Uint8Array, pqRecv: Uint8Array) {
    this.role = role;
    this.pqSend = pqSend;
    this.pqRecv = pqRecv;
    if (this.isOfferor()) this.phase = "offer";
  }

  isOfferor(): boolean {
    const offerorIsInitiator = this.epoch % 2 === 1;
    return this.role === "initiator" ? offerorIsInitiator : !offerorIsInitiator;
  }

  view(): SpqrView {
    const sending = this.offerChunks ?? this.ctChunks;
    const sent = this.offerChunks ? this.sendCursor : this.ctCursor;
    return {
      epoch: this.epoch,
      role: this.isOfferor() ? "offeror" : "encapsulator",
      phase: this.phase,
      chunksSent: sent,
      chunksRecv: this.recv.size,
      chunksTotal: sending?.length ?? this.recvTotal,
      installPending: this.installPending,
      lastInstalled: this.lastInstalled,
    };
  }

  /** Next 0–2 chunks to attach to an outgoing data header. */
  nextSlots(): SpqrSlot[] {
    if (this.isOfferor() && this.phase === "offer") {
      this.ensureOffer();
      return this.take(this.offerChunks!, "sendCursor", 1);
    }
    if (!this.isOfferor() && this.phase === "send-ct" && this.ctChunks) {
      const slots = this.take(this.ctChunks, "ctCursor", 2);
      if (this.ctCursor >= this.ctChunks.length) {
        this.phase = "wait-install";
      }
      return slots;
    }
    return [];
  }

  ingest(slots: SpqrSlot[]): { reconstructed?: "pk" | "ct" } {
    const result: { reconstructed?: "pk" | "ct" } = {};
    for (const s of slots) {
      if (s.type === 0) continue;
      if (this.recvEpoch !== 0 && s.epoch !== this.recvEpoch) continue;
      this.recvEpoch = s.epoch;
      this.recvType = s.type;
      this.recvTotal = s.total;
      this.recv.set(s.idx, s.data);
    }
    const material = reconstruct(this.recv, this.recvTotal);
    if (!material) return result;
    if (this.recvType === 1 && !this.isOfferor()) {
      this.onPk(material);
      result.reconstructed = "pk";
    } else if (this.recvType === 2 && this.isOfferor()) {
      this.onCt(material);
      result.reconstructed = "ct";
    }
    this.recv.clear();
    this.recvTotal = 0;
    this.recvEpoch = 0;
    this.recvType = 0;
    return result;
  }

  /**
   * Install a completed epoch secret into both PQ chains.
   * Called on the offeror's send (flag set) and the encapsulator's decrypt.
   */
  install(ss: Uint8Array): void {
    this.pqSend = mixPq(this.pqSend, ss);
    this.pqRecv = mixPq(this.pqRecv, ss);
    this.lastInstalled = this.epoch;
    this.installPending = false;
    zeroize(ss);
    this.advanceEpoch();
  }

  takeInstallFlag(): number {
    if (this.isOfferor() && this.installPending && this.pendingSs) {
      return this.epoch;
    }
    return 0;
  }

  consumeInstall(epoch: number): void {
    if (!epoch) return;
    if (!this.isOfferor() && this.pendingSs && epoch === this.epoch) {
      this.install(this.pendingSs);
      this.pendingSs = null;
    }
  }

  applyLocalInstall(): void {
    if (this.isOfferor() && this.installPending && this.pendingSs) {
      this.install(this.pendingSs);
      this.pendingSs = null;
    }
  }

  remainingToFlush(): number {
    if (this.isOfferor() && this.phase === "offer") {
      if (!this.offerChunks) return 1;
      return Math.max(0, this.offerChunks.length - this.sendCursor);
    }
    if (this.ctChunks) {
      return Math.max(0, this.ctChunks.length - this.ctCursor);
    }
    return 0;
  }

  private ensureOffer(): void {
    if (this.offerChunks) return;
    const kp = kemKeygen();
    this.offerSk = kp.secretKey;
    this.offerChunks = chunkify(kp.publicKey);
    this.sendCursor = 0;
    this.phase = "offer";
  }

  private take(
    chunks: Uint8Array[],
    cursorKey: "sendCursor" | "ctCursor",
    type: 1 | 2,
  ): SpqrSlot[] {
    const slots: SpqrSlot[] = [];
    for (let i = 0; i < SPQR_CHUNKS_PER_MSG; i++) {
      const idx = this[cursorKey];
      if (idx >= chunks.length) break;
      slots.push({
        epoch: this.epoch,
        type,
        total: chunks.length,
        idx,
        data: chunks[idx]!,
      });
      this[cursorKey] = idx + 1;
    }
    if (
      type === 1 &&
      this.offerChunks &&
      this.sendCursor >= this.offerChunks.length
    ) {
      this.phase = "wait-ct";
    }
    return slots;
  }

  private onPk(pk: Uint8Array): void {
    const { cipherText, sharedSecret } = kemEncaps(pk);
    this.ctChunks = chunkify(cipherText);
    this.ctCursor = 0;
    this.pendingSs = sharedSecret;
    this.phase = "send-ct";
  }

  private onCt(ct: Uint8Array): void {
    if (!this.offerSk) throw new Error("TR_SPQR_NO_SK");
    const ss = kemDecaps(this.offerSk, ct);
    zeroize(this.offerSk);
    this.offerSk = null;
    this.offerChunks = null;
    this.pendingSs = ss;
    this.installPending = true;
    this.phase = "idle";
  }

  private advanceEpoch(): void {
    this.epoch += 1;
    this.offerChunks = null;
    this.ctChunks = null;
    this.sendCursor = 0;
    this.ctCursor = 0;
    this.recv.clear();
    this.phase = this.isOfferor() ? "offer" : "idle";
  }
}

export function chunkify(data: Uint8Array): Uint8Array[] {
  const body = new Uint8Array(4 + data.length);
  writeU32(body, 0, data.length);
  body.set(data, 4);
  const n = Math.ceil(body.length / SPQR_CHUNK);
  const padded = new Uint8Array(n * SPQR_CHUNK);
  padded.set(body);
  const chunks: Uint8Array[] = [];
  const parity = new Uint8Array(SPQR_CHUNK);
  for (let i = 0; i < n; i++) {
    const c = padded.subarray(i * SPQR_CHUNK, (i + 1) * SPQR_CHUNK);
    chunks.push(c);
    for (let j = 0; j < SPQR_CHUNK; j++) parity[j]! ^= c[j]!;
  }
  chunks.push(parity);
  return chunks;
}

export function reconstruct(
  map: Map<number, Uint8Array>,
  total: number,
): Uint8Array | null {
  if (!total || total < 2) return null;
  const nData = total - 1;
  if (map.size < nData) return null;
  const slots: Array<Uint8Array | null> = Array.from({ length: total }, () => null);
  for (const [i, c] of map) {
    if (i >= 0 && i < total) slots[i] = c;
  }
  let missing = -1;
  for (let i = 0; i < nData; i++) {
    if (!slots[i]) {
      if (missing !== -1) return null;
      missing = i;
    }
  }
  if (missing !== -1) {
    const parity = slots[total - 1];
    if (!parity) return null;
    const rec = parity.slice();
    for (let i = 0; i < nData; i++) {
      if (i === missing) continue;
      const c = slots[i]!;
      for (let j = 0; j < SPQR_CHUNK; j++) rec[j]! ^= c[j]!;
    }
    slots[missing] = rec;
  }
  const padded = concat(...(slots.slice(0, nData) as Uint8Array[]));
  const len = readU32(padded, 0);
  if (len > padded.length - 4) return null;
  return padded.subarray(4, 4 + len);
}
