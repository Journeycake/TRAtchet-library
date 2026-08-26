import { aeadOpen, aeadSeal } from "./aead.ts";
import {
  concat,
  fingerprint,
  fromHex,
  fromUtf8,
  toHex,
  utf8,
  zeroize,
} from "./bytes.ts";
import {
  classifyHandshake,
  createInit,
  finishHandshake,
  respondInit,
  type HandshakePending,
  type HandshakeSecrets,
  type Role,
} from "./handshake.ts";
import { decodeHeader, encodeHeader } from "./header.ts";
import { kdfCk, kdfHybrid, kdfInstallMk } from "./kdf.ts";
import { MAX_PLAINTEXT, MAX_SKIP, MAX_SKIPPED_STORE } from "./params.ts";
import { DoubleRatchet } from "./ratchet.ts";
import { SparseRatchet } from "./spqr.ts";

export type Phase = "idle" | "wait-resp" | "established" | "closed";

export type CryptoTrace = {
  direction: "send" | "recv";
  n: number;
  pn: number;
  dhRatchet: boolean;
  ecMkFp: string;
  pqMkFp: string;
  hybridMkFp: string;
  headerLen: number;
  ctLen: number;
  ptLen: number;
  installEpoch: number;
  spqr: {
    epoch: number;
    type: string;
    idx: string;
    total: number;
  };
};

export type SessionSnapshot = {
  phase: Phase;
  role: Role | "unset";
  sessionId: string;
  ns: number;
  nr: number;
  pn: number;
  dhPubFp: string;
  dhRemoteFp: string;
  rkFp: string;
  cksFp: string;
  ckrFp: string;
  pqSendFp: string;
  pqRecvFp: string;
  skipped: number;
  lastHybridFp: string;
  lastEcMkFp: string;
  lastPqMkFp: string;
  pq: ReturnType<SparseRatchet["view"]> | null;
};

type Hybrid = { key: Uint8Array; nonce: Uint8Array };

export class Session {
  phase: Phase = "idle";
  role: Role | "unset" = "unset";
  sessionId: Uint8Array | null = null;
  private pending: HandshakePending | null = null;
  private dr: DoubleRatchet | null = null;
  private pq: SparseRatchet | null = null;
  private skipped = new Map<string, Hybrid>();
  lastTrace: CryptoTrace | null = null;
  lastHybridFp = "";
  lastPqMkFp = "";
  lastError: string | null = null;
  private pendingSendRatchet = false;

  handshakeInit(): Uint8Array {
    this.assertPhase("idle");
    const { msg, pending } = createInit();
    this.pending = pending;
    this.sessionId = pending.sessionId;
    this.role = "initiator";
    this.phase = "wait-resp";
    return msg;
  }

  handshakeRespond(inMsg: Uint8Array): Uint8Array {
    this.assertPhase("idle");
    const { msg, secrets } = respondInit(inMsg);
    this.installSecrets(secrets);
    return msg;
  }

  handshakeFinish(inMsg: Uint8Array): void {
    this.assertPhase("wait-resp");
    if (!this.pending) throw new Error("TR_NO_PENDING");
    const secrets = finishHandshake(inMsg, this.pending);
    this.pending = null;
    this.installSecrets(secrets);
  }

  ingestHandshake(msg: Uint8Array): Uint8Array | null {
    const kind = classifyHandshake(msg);
    if (kind === "init") return this.handshakeRespond(msg);
    if (kind === "resp") {
      this.handshakeFinish(msg);
      return null;
    }
    throw new Error("TR_BAD_HANDSHAKE");
  }

  encrypt(plaintext: Uint8Array): { header: Uint8Array; ciphertext: Uint8Array } {
    this.assertEstablished();
    if (plaintext.length > MAX_PLAINTEXT) throw new Error("TR_PLAINTEXT_TOO_LARGE");
    const dr = this.dr!;
    const pq = this.pq!;
    if (this.pendingSendRatchet) {
      dr.sendingRatchet();
      this.pendingSendRatchet = false;
    }
    const slots = pq.nextSlots();
    const installEpoch = pq.takeInstallFlag();
    const send = dr.sendStep();
    const stepped = kdfCk(pq.pqSend);
    pq.pqSend = stepped.ck;
    let pqMk = stepped.mk;
    if (installEpoch && pq.pendingSs) {
      const mixed = kdfInstallMk(pqMk, pq.pendingSs);
      zeroize(pqMk);
      pqMk = mixed;
    }
    const hybrid = kdfHybrid(send.mk, pqMk);
    this.lastPqMkFp = fingerprint(pqMk);
    this.lastHybridFp = fingerprint(hybrid.key);
    zeroize(send.mk, pqMk);
    if (installEpoch) pq.applyLocalInstall();
    const header = encodeHeader({
      n: send.n,
      pn: send.pn,
      dhPub: send.dhPub,
      installEpoch,
      slots,
    });
    const aad = concat(this.sessionId!, header);
    const ciphertext = aeadSeal(hybrid.key, hybrid.nonce, plaintext, aad);
    zeroize(hybrid.key, hybrid.nonce);
    this.lastTrace = {
      direction: "send",
      n: send.n,
      pn: send.pn,
      dhRatchet: false,
      ecMkFp: dr.lastEcMkFp,
      pqMkFp: this.lastPqMkFp,
      hybridMkFp: this.lastHybridFp,
      headerLen: header.length,
      ctLen: ciphertext.length,
      ptLen: plaintext.length,
      installEpoch,
      spqr: {
        epoch: slots[0]?.epoch ?? pq.epoch,
        type: ["none", "pk", "ct"][slots[0]?.type ?? 0] ?? "none",
        idx: slots.map((s) => String(s.idx)).join(",") || "—",
        total: slots[0]?.total ?? 0,
      },
    };
    return { header, ciphertext };
  }

  decrypt(header: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    this.assertEstablished();
    const dr = this.dr!;
    const pq = this.pq!;
    const h = decodeHeader(header);
    pq.ingest(h.slots);

    const skipped = this.skipped.get(skipId(h.dhPub, h.n));
    if (skipped) {
      this.skipped.delete(skipId(h.dhPub, h.n));
      const aad = concat(this.sessionId!, header);
      const pt = aeadOpen(skipped.key, skipped.nonce, ciphertext, aad);
      zeroize(skipped.key, skipped.nonce);
      this.pendingSendRatchet = true;
      return pt;
    }

    let dhRatchet = false;
    if (!dr.sameRemote(h.dhPub)) {
      this.skipUntil(dr.dhr, h.pn);
      dr.receivingRatchet(h.dhPub);
      dhRatchet = true;
    }
    this.skipUntil(h.dhPub, h.n);

    const ecMk = dr.recvStep();
    const stepped = kdfCk(pq.pqRecv);
    pq.pqRecv = stepped.ck;
    let pqMk = stepped.mk;
    if (h.installEpoch && pq.pendingSs) {
      const mixed = kdfInstallMk(pqMk, pq.pendingSs);
      zeroize(pqMk);
      pqMk = mixed;
    }
    const hybrid = kdfHybrid(ecMk, pqMk);
    this.lastPqMkFp = fingerprint(pqMk);
    this.lastHybridFp = fingerprint(hybrid.key);
    zeroize(ecMk, pqMk);
    if (h.installEpoch) pq.consumeInstall(h.installEpoch);
    const aad = concat(this.sessionId!, header);
    try {
      const pt = aeadOpen(hybrid.key, hybrid.nonce, ciphertext, aad);
      zeroize(hybrid.key, hybrid.nonce);
      this.pendingSendRatchet = true;
      this.lastTrace = {
        direction: "recv",
        n: h.n,
        pn: h.pn,
        dhRatchet,
        ecMkFp: dr.lastEcMkFp,
        pqMkFp: this.lastPqMkFp,
        hybridMkFp: this.lastHybridFp,
        headerLen: header.length,
        ctLen: ciphertext.length,
        ptLen: pt.length,
        installEpoch: h.installEpoch,
        spqr: {
          epoch: h.slots[0]?.epoch ?? pq.epoch,
          type: ["none", "pk", "ct"][h.slots[0]?.type ?? 0] ?? "none",
          idx: h.slots.map((s) => String(s.idx)).join(",") || "—",
          total: h.slots[0]?.total ?? 0,
        },
      };
      return pt;
    } catch (err) {
      zeroize(hybrid.key, hybrid.nonce);
      throw err;
    }
  }

  encryptText(text: string): { header: Uint8Array; ciphertext: Uint8Array } {
    return this.encrypt(utf8(text));
  }

  decryptText(header: Uint8Array, ciphertext: Uint8Array): string {
    return fromUtf8(this.decrypt(header, ciphertext));
  }

  snapshot(): SessionSnapshot {
    const dr = this.dr;
    const pq = this.pq;
    return {
      phase: this.phase,
      role: this.role,
      sessionId: this.sessionId ? toHex(this.sessionId) : "",
      ns: dr?.ns ?? 0,
      nr: dr?.nr ?? 0,
      pn: dr?.pn ?? 0,
      dhPubFp: dr ? fingerprint(dr.dhs.publicKey) : "",
      dhRemoteFp: dr ? fingerprint(dr.dhr) : "",
      rkFp: dr ? fingerprint(dr.rk) : "",
      cksFp: dr ? fingerprint(dr.cks) : "",
      ckrFp: dr ? fingerprint(dr.ckr) : "",
      pqSendFp: pq ? fingerprint(pq.pqSend) : "",
      pqRecvFp: pq ? fingerprint(pq.pqRecv) : "",
      skipped: this.skipped.size,
      lastHybridFp: this.lastHybridFp,
      lastEcMkFp: dr?.lastEcMkFp ?? "",
      lastPqMkFp: this.lastPqMkFp,
      pq: pq ? pq.view() : null,
    };
  }

  remainingPqChunks(): number {
    return this.pq?.remainingToFlush() ?? 0;
  }

  exportState(): Uint8Array {
    this.assertEstablished();
    const dr = this.dr!;
    const pq = this.pq!;
    const obj = {
      v: 1,
      role: this.role,
      sid: toHex(this.sessionId!),
      ns: dr.ns,
      nr: dr.nr,
      pn: dr.pn,
      rk: toHex(dr.rk),
      cks: toHex(dr.cks),
      ckr: toHex(dr.ckr),
      dhsSk: toHex(dr.dhs.secretKey),
      dhsPk: toHex(dr.dhs.publicKey),
      dhr: toHex(dr.dhr),
      pqSend: toHex(pq.pqSend),
      pqRecv: toHex(pq.pqRecv),
      epoch: pq.epoch,
      lastInstalled: pq.lastInstalled,
    };
    return utf8(JSON.stringify(obj));
  }

  importState(buf: Uint8Array): void {
    const obj = JSON.parse(fromUtf8(buf)) as Record<string, string | number>;
    if (obj.v !== 1) throw new Error("TR_STATE_VERSION");
    // Restore is a lab feature; a fresh Session is expected.
    this.free();
    this.role = obj.role as Role;
    this.sessionId = fromHex(String(obj.sid));
    this.phase = "established";
    const secrets: HandshakeSecrets = {
      role: this.role,
      sessionId: this.sessionId,
      root: fromHex(String(obj.rk)),
      ckInit: fromHex(String(obj.cks)),
      ckResp: fromHex(String(obj.ckr)),
      pqInit: fromHex(String(obj.pqSend)),
      pqResp: fromHex(String(obj.pqRecv)),
      dh: {
        secretKey: fromHex(String(obj.dhsSk)),
        publicKey: fromHex(String(obj.dhsPk)),
      },
      dhRemote: fromHex(String(obj.dhr)),
    };
    this.installSecrets(secrets);
    this.dr!.ns = Number(obj.ns);
    this.dr!.nr = Number(obj.nr);
    this.dr!.pn = Number(obj.pn);
    this.dr!.cks = fromHex(String(obj.cks));
    this.dr!.ckr = fromHex(String(obj.ckr));
    this.dr!.rk = fromHex(String(obj.rk));
    this.pq!.pqSend = fromHex(String(obj.pqSend));
    this.pq!.pqRecv = fromHex(String(obj.pqRecv));
    this.pq!.epoch = Number(obj.epoch);
    this.pq!.lastInstalled = Number(obj.lastInstalled);
  }

  free(): void {
    if (this.pending) {
      zeroize(
        this.pending.dh.secretKey,
        this.pending.kem.secretKey,
        this.pending.nonce,
      );
      this.pending = null;
    }
    if (this.dr) {
      zeroize(this.dr.rk, this.dr.cks, this.dr.ckr, this.dr.dhs.secretKey);
    }
    if (this.pq) {
      zeroize(this.pq.pqSend, this.pq.pqRecv, this.pq.offerSk, this.pq.pendingSs);
    }
    for (const v of this.skipped.values()) zeroize(v.key, v.nonce);
    this.skipped.clear();
    this.dr = null;
    this.pq = null;
    this.phase = "closed";
  }

  private installSecrets(secrets: HandshakeSecrets): void {
    this.sessionId = secrets.sessionId;
    this.role = secrets.role;
    this.dr = new DoubleRatchet(secrets);
    const pqSend = secrets.role === "initiator" ? secrets.pqInit : secrets.pqResp;
    const pqRecv = secrets.role === "initiator" ? secrets.pqResp : secrets.pqInit;
    this.pq = new SparseRatchet(secrets.role, pqSend, pqRecv);
    this.phase = "established";
  }

  private skipUntil(dhPub: Uint8Array, until: number): void {
    const dr = this.dr!;
    const pq = this.pq!;
    if (until < dr.nr) return;
    if (until - dr.nr > MAX_SKIP) throw new Error("TR_SKIP_LIMIT");
    while (dr.nr < until) {
      const ec = kdfCk(dr.ckr);
      dr.ckr = ec.ck;
      const pqs = kdfCk(pq.pqRecv);
      pq.pqRecv = pqs.ck;
      const hybrid = kdfHybrid(ec.mk, pqs.mk);
      this.skipped.set(skipId(dhPub, dr.nr), hybrid);
      if (this.skipped.size > MAX_SKIPPED_STORE) {
        const first = this.skipped.keys().next().value;
        if (first) {
          const old = this.skipped.get(first);
          if (old) zeroize(old.key, old.nonce);
          this.skipped.delete(first);
        }
      }
      dr.nr += 1;
    }
  }

  private assertPhase(p: Phase): void {
    if (this.phase !== p) throw new Error(`TR_PHASE:${this.phase}`);
  }

  private assertEstablished(): void {
    if (this.phase !== "established" || !this.dr || !this.pq || !this.sessionId) {
      throw new Error("TR_NOT_ESTABLISHED");
    }
  }
}

function skipId(dh: Uint8Array, n: number): string {
  return `${fingerprint(dh)}:${n}`;
}
