import { sha256 } from "@noble/hashes/sha2.js";
import { create } from "zustand";
import {
  Session,
  classifyHandshake,
  describeHeader,
  fingerprint,
  fromUtf8,
  identityFromSeed,
  toHex,
  utf8,
  type CryptoTrace,
  type SessionSnapshot,
} from "@/lib/tratchet";

export type HostId = "alpha" | "bravo";
export type MobileTab = "alpha" | "wire" | "bravo";

export type ChatLine = {
  id: string;
  dir: "out" | "in";
  kind: "app" | "meta";
  text: string;
  hybridFp: string;
  n: number;
  headerLen: number;
  ctLen: number;
  spqr: string;
  dhRatchet: boolean;
  ts: number;
};

export type WirePacket = {
  id: string;
  from: HostId;
  kind: "init" | "resp" | "data";
  control: boolean;
  bytes: Uint8Array;
  header?: Uint8Array;
  ciphertext?: Uint8Array;
  status: "queued" | "delivered" | "dropped";
  note: string;
  ts: number;
};

type LabState = {
  alpha: SessionSnapshot;
  bravo: SessionSnapshot;
  alphaLog: ChatLine[];
  bravoLog: ChatLine[];
  wire: WirePacket[];
  autoForward: boolean;
  selectedId: string | null;
  lastTrace: CryptoTrace | null;
  error: string | null;
  mobileTab: MobileTab;
  leakedFp: string | null;
  demoRunning: boolean;
  epochNote: string | null;
  beginHandshake: () => void;
  send: (from: HostId, text: string, opts?: { control?: boolean }) => void;
  flushPq: (from: HostId) => number;
  completePqEpoch: () => void;
  deliver: (id: string) => void;
  drop: (id: string) => void;
  setAutoForward: (v: boolean) => void;
  select: (id: string | null) => void;
  reset: () => void;
  leakLastKey: (from: HostId) => void;
  runDemo: () => Promise<void>;
  setMobileTab: (t: MobileTab) => void;
  exportHost: (from: HostId) => string;
};

function labIdentity(tag: "alpha" | "bravo") {
  return identityFromSeed(sha256(utf8(`TRatchet-lab-v2:${tag}`)).subarray(0, 32));
}

function makePinnedPair(): Record<HostId, Session> {
  const idA = labIdentity("alpha");
  const idB = labIdentity("bravo");
  return {
    alpha: new Session({ identity: idA, peerIdentity: idB.publicKey }),
    bravo: new Session({ identity: idB, peerIdentity: idA.publicKey }),
  };
}

let sessions: Record<HostId, Session> = makePinnedPair();

function snap(id: HostId): SessionSnapshot {
  return sessions[id].snapshot();
}

let seq = 0;
function nid(prefix: string): string {
  seq += 1;
  return `${prefix}-${seq}`;
}

function peer(id: HostId): HostId {
  return id === "alpha" ? "bravo" : "alpha";
}

export const useLab = create<LabState>((set, get) => {
  function publish(partial?: Partial<LabState>) {
    set({
      alpha: snap("alpha"),
      bravo: snap("bravo"),
      lastTrace: sessions.alpha.lastTrace ?? sessions.bravo.lastTrace,
      ...partial,
    });
  }

  function fail(err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    set({ error: message });
  }

  function enqueue(
    from: HostId,
    kind: WirePacket["kind"],
    payload: {
      bytes: Uint8Array;
      header?: Uint8Array;
      ciphertext?: Uint8Array;
      note: string;
      control?: boolean;
    },
  ): WirePacket {
    const pkt: WirePacket = {
      id: nid("pkt"),
      from,
      kind,
      control: payload.control ?? false,
      bytes: payload.bytes.slice(),
      header: payload.header?.slice(),
      ciphertext: payload.ciphertext?.slice(),
      status: "queued",
      note: payload.note,
      ts: Date.now(),
    };
    set({ wire: [...get().wire, pkt] });
    if (get().autoForward) deliverInternal(pkt.id);
    return pkt;
  }

  function deliverInternal(id: string) {
    const pkt = get().wire.find((p) => p.id === id);
    if (!pkt || pkt.status !== "queued") return;
    const to = peer(pkt.from);
    try {
      if (pkt.kind === "init" || pkt.kind === "resp") {
        const reply = sessions[to].ingestHandshake(pkt.bytes);
        set({
          wire: get().wire.map((p) =>
            p.id === id ? { ...p, status: "delivered" } : p,
          ),
        });
        if (reply) {
          const kind = classifyHandshake(reply) === "resp" ? "resp" : "init";
          enqueue(to, kind, {
            bytes: reply,
            note: kind === "resp" ? "Handshake response · Ed25519 signed" : "Handshake init",
          });
        }
        publish();
        return;
      }
      if (!pkt.header || !pkt.ciphertext) throw new Error("TR_WIRE_DATA");
      const pt = sessions[to].decrypt(pkt.header, pkt.ciphertext);
      const text = fromUtf8(pt);
      const desc = describeHeader(pkt.header);
      const control = pkt.control || text.length === 0;
      set({
        wire: get().wire.map((p) =>
          p.id === id ? { ...p, status: "delivered" } : p,
        ),
      });
      if (!control) {
        const line: ChatLine = {
          id: nid("msg"),
          dir: "in",
          kind: "app",
          text,
          hybridFp: sessions[to].lastHybridFp,
          n: desc.n,
          headerLen: pkt.header.length,
          ctLen: pkt.ciphertext.length,
          spqr: `${desc.spqrType} ${desc.spqrIdx}/${desc.spqrTotal || "—"}`,
          dhRatchet: sessions[to].lastTrace?.dhRatchet ?? false,
          ts: Date.now(),
        };
        const key = to === "alpha" ? "alphaLog" : "bravoLog";
        set({ [key]: [...get()[key], line] } as Partial<LabState>);
      }
      publish();
    } catch (err) {
      fail(err);
    }
  }

  return {
    alpha: snap("alpha"),
    bravo: snap("bravo"),
    alphaLog: [],
    bravoLog: [],
    wire: [],
    autoForward: true,
    selectedId: null,
    lastTrace: null,
    error: null,
    mobileTab: "alpha",
    leakedFp: null,
    demoRunning: false,
    epochNote: null,

    beginHandshake: () => {
      try {
        set({ error: null });
        const msg = sessions.alpha.handshakeInit();
        enqueue("alpha", "init", {
          bytes: msg,
          note: `Initiator offer · Ed25519 signed · ${msg.length} B`,
        });
        publish();
      } catch (err) {
        fail(err);
      }
    },

    send: (from, text, opts) => {
      const control = opts?.control === true;
      const trimmed = text.trim();
      if (!control && !trimmed) return;
      try {
        set({ error: null });
        const sealed = sessions[from].encrypt(utf8(control ? "" : trimmed));
        const desc = describeHeader(sealed.header);
        const spqr = `${desc.spqrType} ${desc.spqrIdx}/${desc.spqrTotal || "—"}`;
        if (!control) {
          const line: ChatLine = {
            id: nid("msg"),
            dir: "out",
            kind: "app",
            text: trimmed,
            hybridFp: sessions[from].lastHybridFp,
            n: desc.n,
            headerLen: sealed.header.length,
            ctLen: sealed.ciphertext.length,
            spqr,
            dhRatchet: false,
            ts: Date.now(),
          };
          const key = from === "alpha" ? "alphaLog" : "bravoLog";
          set({ [key]: [...get()[key], line] } as Partial<LabState>);
        }
        const framed = new Uint8Array(sealed.header.length + sealed.ciphertext.length);
        framed.set(sealed.header, 0);
        framed.set(sealed.ciphertext, sealed.header.length);
        enqueue(from, "data", {
          bytes: framed,
          header: sealed.header,
          ciphertext: sealed.ciphertext,
          control,
          note: control
            ? `SPQR ${spqr} · empty payload · n=${desc.n}`
            : `DATA n=${desc.n} · hdr ${sealed.header.length}B · ct ${sealed.ciphertext.length}B`,
        });
        publish();
      } catch (err) {
        fail(err);
      }
    },

    flushPq: (from) => {
      let frames = 0;
      while (sessions[from].remainingPqChunks() > 0 && frames < 40) {
        get().send(from, "", { control: true });
        frames += 1;
      }
      if (frames > 0) {
        const key = from === "alpha" ? "alphaLog" : "bravoLog";
        const line: ChatLine = {
          id: nid("msg"),
          dir: "out",
          kind: "meta",
          text: `SPQR flush · ${frames} empty in-band frame${frames === 1 ? "" : "s"} · chunks only, no application payload`,
          hybridFp: sessions[from].lastHybridFp,
          n: sessions[from].snapshot().ns,
          headerLen: 176,
          ctLen: 16,
          spqr: "flush",
          dhRatchet: false,
          ts: Date.now(),
        };
        set({ [key]: [...get()[key], line] } as Partial<LabState>);
      }
      return frames;
    },

    completePqEpoch: () => {
      const pkFrames = get().flushPq("alpha");
      const ctFrames = get().flushPq("bravo");
      let install = 0;
      if (sessions.alpha.snapshot().pq?.installPending) {
        get().send("alpha", "", { control: true });
        install = 1;
      }
      const total = pkFrames + ctFrames + install;
      set({
        epochNote:
          total > 0
            ? `PQ epoch used ${total} empty in-band frames (${pkFrames} PK + ${ctFrames} CT${install ? " + 1 install" : ""}). ML-KEM-768 keys are 1,184 / 1,088 bytes; the 176-byte header only carries 128 bytes of chunks, so a quiet session must pad. Real traffic amortizes this — chunks ride on application messages.`
            : "No outstanding SPQR chunks. Keep sending payloads and the epoch will close on its own.",
      });
    },

    deliver: (id) => deliverInternal(id),

    drop: (id) => {
      set({
        wire: get().wire.map((p) =>
          p.id === id && p.status === "queued" ? { ...p, status: "dropped" } : p,
        ),
      });
    },

    setAutoForward: (v) => set({ autoForward: v }),
    select: (id) => set({ selectedId: id }),

    reset: () => {
      sessions.alpha.free();
      sessions.bravo.free();
      sessions = makePinnedPair();
      seq = 0;
      set({
        alpha: snap("alpha"),
        bravo: snap("bravo"),
        alphaLog: [],
        bravoLog: [],
        wire: [],
        selectedId: null,
        lastTrace: null,
        error: null,
        leakedFp: null,
        demoRunning: false,
        epochNote: null,
      });
    },

    leakLastKey: (from) => {
      const fp = sessions[from].lastHybridFp;
      set({ leakedFp: fp || null });
    },

    runDemo: async () => {
      const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
      get().reset();
      set({ demoRunning: true, autoForward: true, error: null });
      await wait(80);
      get().beginHandshake();
      await wait(220);
      get().send("alpha", "session layer up");
      await wait(180);
      get().send("bravo", "hybrid lock confirmed");
      await wait(180);
      get().send("alpha", "forward secrecy holds");
      set({ demoRunning: false });
    },

    setMobileTab: (t) => set({ mobileTab: t }),

    exportHost: (from) => {
      try {
        return toHex(sessions[from].exportState());
      } catch (err) {
        fail(err);
        return "";
      }
    },
  };
});

export function inspectPacket(pkt: WirePacket) {
  if (pkt.kind === "data" && pkt.header) {
    return { handshake: false as const, header: describeHeader(pkt.header), hex: toHex(pkt.bytes) };
  }
  return {
    handshake: true as const,
    kind: classifyHandshake(pkt.bytes),
    hex: toHex(pkt.bytes),
    fp: fingerprint(pkt.bytes),
    len: pkt.bytes.length,
  };
}
