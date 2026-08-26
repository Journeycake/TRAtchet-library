/** Two independent Node sessions talking over a kernel socket. */

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fingerprint, fromUtf8, utf8 } from "./bytes.ts";
import {
  classifyRecord,
  encodeRecord,
  RecordParser,
  splitDataRecord,
} from "./framing.ts";
import { describeHeader } from "./header.ts";
import { RECORD_LEN_SIZE } from "./params.ts";
import { Session } from "./session.ts";
import type {
  HostId,
  HostPairEvent,
  HostPairResult,
  HostTransport,
} from "./host-types.ts";

const READ_MS = 8000;

class PeerLink {
  private parser = new RecordParser();
  private pending: Uint8Array[] = [];
  private waiter: {
    resolve: (r: Uint8Array) => void;
    reject: (e: Error) => void;
  } | null = null;
  private sock: net.Socket;

  constructor(sock: net.Socket) {
    this.sock = sock;
    sock.on("data", (chunk: Buffer) => {
      try {
        for (const rec of this.parser.push(new Uint8Array(chunk))) {
          if (this.waiter) {
            const w = this.waiter;
            this.waiter = null;
            w.resolve(rec);
          } else {
            this.pending.push(rec);
          }
        }
      } catch (err) {
        this.fail(err);
      }
    });
    sock.on("error", (err) => this.fail(err));
    sock.on("end", () => this.fail(new Error("TR_PEER_CLOSED")));
  }

  read(): Promise<Uint8Array> {
    if (this.pending.length > 0) return Promise.resolve(this.pending.shift()!);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new Error("TR_READ_TIMEOUT"));
      }, READ_MS);
      this.waiter = {
        resolve: (r) => {
          clearTimeout(timer);
          resolve(r);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      };
    });
  }

  write(payload: Uint8Array): Promise<number> {
    const rec = encodeRecord(payload);
    return new Promise((resolve, reject) => {
      this.sock.write(rec, (err) => (err ? reject(err) : resolve(rec.length)));
    });
  }

  private fail(err: unknown) {
    const e = err instanceof Error ? err : new Error(String(err));
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      w.reject(e);
    }
  }
}

type Opened = {
  server: net.Server;
  client: net.Socket;
  accepted: net.Socket;
  bind: string;
  sockPath?: string;
  sockDir?: string;
};

async function openPair(transport: HostTransport): Promise<Opened> {
  const server = net.createServer();
  server.maxConnections = 1;

  let sockPath: string | undefined;
  let sockDir: string | undefined;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    if (transport === "unix") {
      sockDir = fs.mkdtempSync(path.join(os.tmpdir(), "tratchet-"));
      fs.chmodSync(sockDir, 0o700);
      sockPath = path.join(sockDir, "s");
      server.listen(sockPath, () => {
        try {
          fs.chmodSync(sockPath!, 0o600);
        } catch {
          /* best-effort */
        }
        resolve();
      });
    } else {
      server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, resolve);
    }
  });

  const bind =
    transport === "unix"
      ? `unix ${sockPath}`
      : `tcp ${(server.address() as net.AddressInfo).port}`;

  const acceptedP = new Promise<net.Socket>((resolve, reject) => {
    server.once("connection", resolve);
    server.once("error", reject);
  });

  const client = await new Promise<net.Socket>((resolve, reject) => {
    const onReady = (s: net.Socket) => {
      s.off("error", reject);
      resolve(s);
    };
    const s = sockPath
      ? net.connect(sockPath, () => onReady(s))
      : net.connect(
          {
            host: "127.0.0.1",
            port: (server.address() as net.AddressInfo).port,
          },
          () => onReady(s),
        );
    s.once("error", reject);
  });

  const accepted = await acceptedP;
  return { server, client, accepted, bind, sockPath, sockDir };
}

export async function runHostPair(opts: {
  transport: HostTransport;
  flushEpoch: boolean;
}): Promise<HostPairResult> {
  const t0 = Date.now();
  const events: HostPairEvent[] = [];
  const push = (e: Omit<HostPairEvent, "t">) =>
    events.push({ t: Date.now() - t0, ...e });

  const alpha = new Session();
  const bravo = new Session();
  const opened = await openPair(opts.transport);
  let records = 0;
  let bytesOnWire = 0;

  const noteBytes = (n: number) => {
    records += 1;
    bytesOnWire += n;
  };

  push({
    host: "bravo",
    kind: "bind",
    text:
      opts.transport === "unix"
        ? "Unix domain socket · no port · same-host only"
        : `TCP stream · ephemeral port ${opened.bind.replace(/^tcp /, "")}`,
  });

  const alphaLink = new PeerLink(opened.client);
  const bravoLink = new PeerLink(opened.accepted);

  push({ host: "alpha", kind: "connect", text: "connected to peer" });
  push({ host: "bravo", kind: "accept", text: "accepted initiator" });

  const sendApp = async (from: HostId, text: string, control = false) => {
    const sess = from === "alpha" ? alpha : bravo;
    const other = from === "alpha" ? bravo : alpha;
    const out = from === "alpha" ? alphaLink : bravoLink;
    const inn = from === "alpha" ? bravoLink : alphaLink;
    const sealed = sess.encrypt(utf8(control ? "" : text));
    const payload = new Uint8Array(sealed.header.length + sealed.ciphertext.length);
    payload.set(sealed.header, 0);
    payload.set(sealed.ciphertext, sealed.header.length);
    const onWire = await out.write(payload);
    noteBytes(onWire);
    const rec = await inn.read();
    const { header, ciphertext } = splitDataRecord(rec);
    const pt = other.decrypt(header, ciphertext);
    const desc = describeHeader(header);
    const spqr = `${desc.spqrType} ${desc.spqrIdx}/${desc.spqrTotal || "—"}`;
    push({
      host: from,
      kind: control ? "control" : "data",
      text: control ? `SPQR ${spqr} · empty payload` : fromUtf8(pt),
      bytes: onWire,
      n: desc.n,
      mkFp: sess.lastHybridFp,
      spqr,
    });
  };

  try {
    const init = alpha.handshakeInit();
    const initBytes = await alphaLink.write(init);
    noteBytes(initBytes);
    push({
      host: "alpha",
      kind: "handshake",
      text: `PQXDH init · ${init.length} B payload + ${RECORD_LEN_SIZE} B length`,
      bytes: initBytes,
    });

    const initRec = await bravoLink.read();
    if (classifyRecord(initRec) !== "init") throw new Error("TR_EXPECT_INIT");
    const resp = bravo.ingestHandshake(initRec);
    if (!resp) throw new Error("TR_NO_RESP");
    const respBytes = await bravoLink.write(resp);
    noteBytes(respBytes);
    push({
      host: "bravo",
      kind: "handshake",
      text: `PQXDH resp · ${resp.length} B payload + ${RECORD_LEN_SIZE} B length`,
      bytes: respBytes,
    });

    const respRec = await alphaLink.read();
    alpha.ingestHandshake(respRec);
    push({
      host: "wire",
      kind: "info",
      text: `session ${fingerprint(alpha.sessionId!)} established over ${opts.transport}`,
    });

    await sendApp("alpha", "session-layer up from alpha");
    await sendApp("bravo", "ack from bravo");
    await sendApp("alpha", "linux-to-linux over the same library");

    if (opts.flushEpoch) {
      let flushed = 0;
      while (alpha.remainingPqChunks() > 0 && flushed < 40) {
        await sendApp("alpha", "", true);
        flushed += 1;
      }
      while (bravo.remainingPqChunks() > 0 && flushed < 80) {
        await sendApp("bravo", "", true);
        flushed += 1;
      }
      if (alpha.snapshot().pq?.installPending) {
        await sendApp("alpha", "", true);
      }
      await sendApp("alpha", "pq epoch mixed into both chains");
    }

    opened.client.end();
    opened.accepted.end();
    push({ host: "wire", kind: "close", text: "stream closed" });

    const snap = (s: Session) => {
      const v = s.snapshot();
      return {
        ns: v.ns,
        nr: v.nr,
        lastMk: v.lastHybridFp,
        pqPhase: v.pq?.phase ?? "none",
        pqEpoch: v.pq?.epoch ?? 0,
      };
    };

    return {
      transport: opts.transport,
      bind: opened.bind,
      bindKind: opts.transport,
      sessionId: alpha.snapshot().sessionId,
      events,
      alpha: snap(alpha),
      bravo: snap(bravo),
      records,
      bytesOnWire,
      durationMs: Date.now() - t0,
    };
  } finally {
    opened.client.destroy();
    opened.accepted.destroy();
    await new Promise<void>((resolve) => opened.server.close(() => resolve()));
    if (opened.sockPath) {
      try {
        fs.unlinkSync(opened.sockPath);
      } catch {
        /* already gone */
      }
    }
    if (opened.sockDir) {
      try {
        fs.rmdirSync(opened.sockDir);
      } catch {
        /* already gone */
      }
    }
    alpha.free();
    bravo.free();
  }
}
