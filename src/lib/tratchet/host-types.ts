export type HostTransport = "tcp" | "unix";
export type HostId = "alpha" | "bravo";

export type HostPairEvent = {
  t: number;
  host: HostId | "wire";
  kind:
    | "bind"
    | "accept"
    | "connect"
    | "handshake"
    | "data"
    | "control"
    | "close"
    | "info";
  text: string;
  bytes?: number;
  n?: number;
  mkFp?: string;
  spqr?: string;
};

export type HostPairSnap = {
  ns: number;
  nr: number;
  lastMk: string;
  pqPhase: string;
  pqEpoch: number;
};

export type HostPairResult = {
  transport: HostTransport;
  bind: string;
  bindKind: HostTransport;
  sessionId: string;
  events: HostPairEvent[];
  alpha: HostPairSnap;
  bravo: HostPairSnap;
  records: number;
  bytesOnWire: number;
  durationMs: number;
};
