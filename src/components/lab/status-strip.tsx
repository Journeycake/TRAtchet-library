"use client";

import { Badge } from "@/components/ui/badge";
import { useLab } from "@/lib/lab-store";
import { shortHex } from "@/lib/utils";

export function StatusStrip() {
  const alpha = useLab((s) => s.alpha);
  const bravo = useLab((s) => s.bravo);
  const established =
    alpha.phase === "established" && bravo.phase === "established";
  const pq = alpha.pq;
  const progress =
    pq && pq.chunksTotal
      ? Math.min(100, Math.round((pq.chunksSent / pq.chunksTotal) * 100))
      : 0;

  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border bg-bg-elevated px-4 py-2.5 lg:px-6">
      <Led on={established} />
      <span className="font-mono text-xs text-muted">
        {established ? "session established" : "waiting on handshake"}
      </span>
      {alpha.sessionId ? (
        <Badge tone="accent">sid {shortHex(alpha.sessionId, 8)}</Badge>
      ) : (
        <Badge>no session</Badge>
      )}
      <span className="hidden h-3 w-px bg-border sm:block" />
      <Badge tone={established ? "ok" : "muted"}>X25519</Badge>
      <Badge tone={established ? "ok" : "muted"}>ML-KEM-768</Badge>
      <Badge tone={established ? "ok" : "muted"}>XChaCha20-Poly1305</Badge>
      {pq ? (
        <div className="ml-auto flex min-w-40 items-center gap-2">
          <span className="font-mono text-xs text-muted">
            PQ epoch {pq.epoch} · {pq.phase}
          </span>
          <div className="h-1.5 w-24 overflow-hidden rounded-full bg-bg-subtle">
            <div
              className="h-full bg-accent transition-[width] duration-200 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      ) : (
        <span className="ml-auto font-mono text-xs text-subtle">
          hybrid lock idle
        </span>
      )}
    </div>
  );
}

function Led({ on }: { on: boolean }) {
  return (
    <span
      className={
        on
          ? "size-2 shrink-0 rounded-full bg-accent"
          : "size-2 shrink-0 rounded-full bg-subtle"
      }
      aria-hidden
    />
  );
}
