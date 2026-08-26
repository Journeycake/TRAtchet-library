"use client";

import { useState } from "react";
import { Cable, Play, Server } from "lucide-react";
import { LabNav } from "@/components/lab/lab-nav";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { runLinuxHostPair, type HostPairEvent, type HostPairResult, type HostTransport } from "@/lib/host-pair";
import { cn, shortHex } from "@/lib/utils";

export function HostsPage() {
  const [transport, setTransport] = useState<HostTransport>("tcp");
  const [flushEpoch, setFlushEpoch] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<HostPairResult | null>(null);
  const [tab, setTab] = useState<"alpha" | "wire" | "bravo">("wire");

  async function run() {
    setRunning(true);
    setError(null);
    try {
      const next = await runLinuxHostPair({ data: { transport, flushEpoch } });
      setResult(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="lab-grid lab-shell bg-bg text-fg">
      <LabNav
        current="hosts"
        actions={
          <Button onClick={() => void run()} disabled={running} size="sm">
            <Play className="size-3.5" />
            {running ? "Running" : "Run host pair"}
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-3 border-b border-border bg-bg-elevated px-4 py-2 lg:px-6">
        <span className="font-mono text-xs text-muted">transport</span>
        <Toggle
          value={transport}
          onChange={setTransport}
          options={[
            { id: "tcp", label: "TCP stream" },
            { id: "unix", label: "Unix socket" },
          ]}
        />
        <label className="flex h-11 items-center gap-2 font-mono text-xs text-muted">
          <input
            type="checkbox"
            className="size-4 accent-accent"
            checked={flushEpoch}
            onChange={(e) => setFlushEpoch(e.target.checked)}
          />
          finish PQ epoch
        </label>
        {result ? (
          <span className="ml-auto truncate font-mono text-xs text-subtle">
            {result.bind} · {result.records} records · {result.bytesOnWire} B
          </span>
        ) : (
          <span className="ml-auto hidden font-mono text-xs text-subtle lg:inline">
            same library, kernel socket, no I/O in TRatchet
          </span>
        )}
      </div>

      {error ? (
        <div className="border-b border-danger/30 bg-danger/10 px-4 py-2 font-mono text-sm text-danger">
          {error}
        </div>
      ) : null}

      <p className="border-b border-border px-4 py-2 text-sm leading-relaxed text-muted lg:px-6">
        No well-known port is part of the protocol. Use TCP when the peer is
        another machine (a stable port only helps allowlists). Use a Unix
        socket for two processes on the same host — no port, filesystem
        permissions, cannot leave the box.
      </p>

      {result ? (
        <>
          <div className="flex gap-1 border-b border-border px-2 py-1 lg:hidden">
            {(["alpha", "wire", "bravo"] as const).map((id) => (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={cn(
                  "h-11 flex-1 rounded-md font-mono text-xs capitalize",
                  tab === id ? "bg-bg-subtle text-fg" : "text-muted",
                )}
              >
                {id === "alpha" ? "Alpha" : id === "bravo" ? "Bravo" : "Stream"}
              </button>
            ))}
          </div>
          <ResultView result={result} tab={tab} />
        </>
      ) : (
        <EmptyState />
      )}
    </div>
  );
}

function ResultView({
  result,
  tab,
}: {
  result: HostPairResult;
  tab: "alpha" | "wire" | "bravo";
}) {
  return (
    <div className="lab-main mx-auto w-full max-w-7xl gap-3 p-3 lg:gap-4 lg:p-4">
      <div className={cn("min-h-0 overflow-hidden", tab === "alpha" ? "flex h-full" : "hidden lg:flex")}>
        <HostLog
          id="alpha"
          snap={result.alpha}
          events={result.events.filter((e) => e.host === "alpha")}
        />
      </div>
      <div className={cn("min-h-0 overflow-hidden", tab === "wire" ? "flex h-full" : "hidden lg:flex")}>
        <WireLog events={result.events} sessionId={result.sessionId} />
      </div>
      <div className={cn("min-h-0 overflow-hidden", tab === "bravo" ? "flex h-full" : "hidden lg:flex")}>
        <HostLog
          id="bravo"
          snap={result.bravo}
          events={result.events.filter((e) => e.host === "bravo")}
        />
      </div>
    </div>
  );
}

function HostLog({
  id,
  snap,
  events,
}: {
  id: "alpha" | "bravo";
  snap: HostPairResult["alpha"];
  events: HostPairEvent[];
}) {
  return (
    <section className="flex h-full min-h-0 w-full flex-col rounded-xl bg-bg-elevated shadow-[var(--shadow-border)]">
      <header className="flex items-center gap-3 border-b border-border px-4 py-3">
        <div className="flex size-9 items-center justify-center rounded-md bg-bg-subtle font-mono text-sm text-accent">
          {id === "alpha" ? "A" : "B"}
        </div>
        <div className="min-w-0">
          <h2 className="text-sm font-medium text-fg">
            {id === "alpha" ? "Host Alpha" : "Host Bravo"}
          </h2>
          <p className="font-mono text-xs text-muted">Node · {id === "alpha" ? "initiator" : "responder"}</p>
        </div>
        <Server className="ml-auto size-4 text-subtle" />
      </header>
      <dl className="grid grid-cols-3 gap-px bg-border">
        <Stat k="Ns" v={snap.ns} compact />
        <Stat k="Nr" v={snap.nr} compact />
        <Stat k="PQ" v={snap.pqPhase} compact />
      </dl>
      <ol className="flex flex-1 flex-col gap-1 overflow-y-auto p-3">
        {groupEvents(events).map((row) =>
          row.type === "burst" ? (
            <li key={row.key} className="font-mono text-xs text-muted">
              SPQR burst · {row.count} empty in-band frames
            </li>
          ) : (
            <li key={row.event.t + row.event.text} className="font-mono text-xs text-fg">
              <span className="text-subtle">{pad(row.event.t)} </span>
              {row.event.text}
            </li>
          ),
        )}
      </ol>
    </section>
  );
}

function WireLog({
  events,
  sessionId,
}: {
  events: HostPairEvent[];
  sessionId: string;
}) {
  return (
    <section className="flex h-full min-h-0 w-full flex-col rounded-xl bg-bg-elevated shadow-[var(--shadow-border)]">
      <header className="flex items-center gap-2 border-b border-border px-4 py-3">
        <Cable className="size-4 text-accent" />
        <div>
          <h2 className="text-sm font-medium text-fg">Kernel stream</h2>
          <p className="font-mono text-xs text-muted">length-prefixed records</p>
        </div>
      </header>
      <div className="border-b border-border px-4 py-2">
        <Badge tone="accent">sid {shortHex(sessionId, 8)}</Badge>
      </div>
      <ol className="flex flex-1 flex-col gap-1 overflow-y-auto p-3">
        {groupEvents(events).map((row) =>
          row.type === "burst" ? (
            <li key={row.key} className="flex gap-2 font-mono text-xs text-muted">
              <span className="w-6 shrink-0">{row.host === "alpha" ? "A→" : "B→"}</span>
              <span>spqr burst · {row.count} frames</span>
            </li>
          ) : (
            <li key={row.event.t + row.event.kind + row.event.text} className="flex gap-2 font-mono text-xs">
              <span
                className={cn(
                  "w-6 shrink-0",
                  row.event.host === "alpha" ? "text-accent" : "text-muted",
                )}
              >
                {row.event.host === "alpha" ? "A→" : row.event.host === "bravo" ? "B→" : "·"}
              </span>
              <span className="min-w-0 flex-1 text-fg">
                <span className="text-subtle">{row.event.kind} </span>
                {row.event.text}
                {row.event.bytes != null ? (
                  <span className="text-subtle"> · {row.event.bytes} B</span>
                ) : null}
              </span>
            </li>
          ),
        )}
      </ol>
    </section>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-1 items-center justify-center px-4">
      <p className="max-w-md text-center text-sm text-muted">
        Run the host pair. Bravo binds, Alpha connects, they complete the
        online handshake, then three application records cross the socket.
      </p>
    </div>
  );
}

function Stat({
  k,
  v,
  compact,
}: {
  k: string;
  v: string | number;
  compact?: boolean;
}) {
  return (
    <div className={cn("bg-bg-elevated", compact ? "px-3 py-2" : "px-4 py-3")}>
      <dt className="font-mono text-xs text-subtle">{k}</dt>
      <dd className="truncate font-mono text-xs tabular text-fg">{v}</dd>
    </div>
  );
}

function Toggle<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { id: T; label: string }[];
}) {
  return (
    <div className="flex rounded-md bg-bg-subtle p-1">
      {options.map((opt) => (
        <button
          key={opt.id}
          type="button"
          onClick={() => onChange(opt.id)}
          className={cn(
            "h-11 rounded-sm px-3 font-mono text-xs",
            value === opt.id ? "bg-bg-elevated text-fg shadow-[var(--shadow-border)]" : "text-muted",
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

function pad(ms: number): string {
  return `+${String(ms).padStart(4, "0")}ms`;
}

type EventRow =
  | { type: "one"; event: HostPairEvent }
  | { type: "burst"; key: string; host: HostPairEvent["host"]; count: number };

function groupEvents(events: HostPairEvent[]): EventRow[] {
  const rows: EventRow[] = [];
  let i = 0;
  while (i < events.length) {
    const ev = events[i]!;
    if (ev.kind === "control") {
      const start = i;
      while (
        i < events.length &&
        events[i]!.kind === "control" &&
        events[i]!.host === ev.host
      ) {
        i += 1;
      }
      const batch = events.slice(start, i);
      if (batch.length >= 3) {
        rows.push({
          type: "burst",
          key: `${ev.host}-${ev.t}`,
          host: ev.host,
          count: batch.length,
        });
      } else {
        for (const e of batch) rows.push({ type: "one", event: e });
      }
    } else {
      rows.push({ type: "one", event: ev });
      i += 1;
    }
  }
  return rows;
}
