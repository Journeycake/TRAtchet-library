"use client";

import { useState, type FormEvent } from "react";
import { ArrowUpRight, Download, Lock, Send, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useLab, type HostId } from "@/lib/lab-store";
import { cn, shortHex } from "@/lib/utils";

export function HostPanel({ id }: { id: HostId }) {
  const snap = useLab((s) => s[id]);
  const log = useLab((s) => (id === "alpha" ? s.alphaLog : s.bravoLog));
  const send = useLab((s) => s.send);
  const beginHandshake = useLab((s) => s.beginHandshake);
  const flushPq = useLab((s) => s.flushPq);
  const leakLastKey = useLab((s) => s.leakLastKey);
  const exportHost = useLab((s) => s.exportHost);
  const demoRunning = useLab((s) => s.demoRunning);
  const [draft, setDraft] = useState("");
  const ready = snap.phase === "established";
  const isAlpha = id === "alpha";
  const label = isAlpha ? "Host Alpha" : "Host Bravo";
  const role = isAlpha ? "initiator" : "responder";

  function onSend(e: FormEvent) {
    e.preventDefault();
    send(id, draft);
    setDraft("");
  }

  return (
    <section className="flex h-full min-h-0 w-full flex-col rounded-xl bg-bg-elevated shadow-[var(--shadow-border)]">
      <header className="flex items-center gap-3 border-b border-border px-4 py-3">
        <div className="flex size-9 items-center justify-center rounded-md bg-bg-subtle font-mono text-sm text-accent">
          {isAlpha ? "A" : "B"}
        </div>
        <div className="min-w-0">
          <h2 className="text-sm font-medium text-fg">{label}</h2>
          <p className="font-mono text-xs text-muted">{role}</p>
        </div>
        <Badge
          tone={
            snap.phase === "established"
              ? "ok"
              : snap.phase === "wait-resp"
                ? "warn"
                : "muted"
          }
          className="ml-auto"
        >
          {snap.phase}
        </Badge>
      </header>

      <dl className="grid grid-cols-2 gap-px bg-border sm:grid-cols-4">
        <Stat k="Ns" v={snap.ns} />
        <Stat k="Nr" v={snap.nr} />
        <Stat k="DH" v={shortHex(snap.dhPubFp, 6)} />
        <Stat k="MK" v={shortHex(snap.lastHybridFp, 6)} />
      </dl>

      {snap.pq ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2">
          <span className="font-mono text-xs text-muted">
            SPQR {snap.pq.role} · epoch {snap.pq.epoch}
          </span>
          <Badge tone="accent">{snap.pq.phase}</Badge>
          {snap.pq.chunksTotal > 0 ? (
            <span className="font-mono text-xs text-subtle">
              {snap.pq.chunksSent}/{snap.pq.chunksTotal} sent · {snap.pq.chunksRecv} recv
            </span>
          ) : null}
        </div>
      ) : null}

      <div className="flex min-h-48 flex-1 flex-col gap-2 overflow-y-auto p-4">
        {log.length === 0 ? (
          <p className="m-auto max-w-xs text-center text-sm text-muted">
            {isAlpha
              ? "Start the online handshake, then send a payload. The library never opens a socket."
              : "Responder waits online. Handshake init is accepted on the wire."}
          </p>
        ) : (
          log.map((line) =>
            line.kind === "meta" ? (
              <p
                key={line.id}
                className="mx-auto max-w-md text-center font-mono text-xs text-muted"
              >
                {line.text}
              </p>
            ) : (
              <article
                key={line.id}
                className={cn(
                  "max-w-sm rounded-lg px-3 py-2",
                  line.dir === "out" ? "ml-auto bg-accent-dim" : "bg-bg-subtle",
                )}
              >
                <p className="text-sm text-fg">{line.text}</p>
                <p className="mt-1 font-mono text-xs text-muted">
                  n={line.n} · mk {shortHex(line.hybridFp, 8)}
                  {line.dhRatchet ? " · DH ratchet" : ""} · {line.spqr}
                </p>
              </article>
            ),
          )
        )}
      </div>

      <div className="flex flex-col gap-2 border-t border-border p-3">
        {!ready && isAlpha ? (
          <Button
            onClick={beginHandshake}
            disabled={demoRunning || snap.phase !== "idle"}
          >
            <Lock className="size-4" />
            Begin handshake
          </Button>
        ) : null}
        <form onSubmit={onSend} className="flex gap-2">
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={ready ? "Plaintext payload" : "Establish session first"}
            disabled={!ready}
            maxLength={1100}
            aria-label={`${label} message`}
          />
          <Button type="submit" size="icon" disabled={!ready || !draft.trim()} aria-label="Send">
            <Send className="size-4" />
          </Button>
        </form>
        <div className="flex flex-wrap gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            disabled={!ready}
            onClick={() => flushPq(id)}
          >
            <Zap className="size-3.5" />
            Flush PQ chunks
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={!ready || !snap.lastHybridFp}
            onClick={() => leakLastKey(id)}
          >
            <ArrowUpRight className="size-3.5" />
            Leak last MK
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={!ready}
            onClick={() => {
              const hex = exportHost(id);
              if (hex) void navigator.clipboard?.writeText(hex);
            }}
          >
            <Download className="size-3.5" />
            Export
          </Button>
        </div>
      </div>
    </section>
  );
}

function Stat({ k, v }: { k: string; v: string | number }) {
  return (
    <div className="bg-bg-elevated px-3 py-2">
      <dt className="font-mono text-xs text-subtle">{k}</dt>
      <dd className="font-mono text-xs tabular text-fg">{v}</dd>
    </div>
  );
}
