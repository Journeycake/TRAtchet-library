"use client";

import { Cable } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { inspectPacket, useLab, type WirePacket } from "@/lib/lab-store";
import { cn } from "@/lib/utils";

type WireRow =
  | { type: "one"; pkt: WirePacket }
  | { type: "burst"; from: WirePacket["from"]; packets: WirePacket[] };

function groupWire(wire: WirePacket[]): WireRow[] {
  const rows: WireRow[] = [];
  let i = 0;
  while (i < wire.length) {
    const pkt = wire[i]!;
    if (pkt.control) {
      const start = i;
      while (
        i < wire.length &&
        wire[i]!.control &&
        wire[i]!.from === pkt.from
      ) {
        i += 1;
      }
      const packets = wire.slice(start, i);
      if (packets.length >= 3) rows.push({ type: "burst", from: pkt.from, packets });
      else for (const p of packets) rows.push({ type: "one", pkt: p });
    } else {
      rows.push({ type: "one", pkt });
      i += 1;
    }
  }
  return rows;
}

export function WirePanel() {
  const wire = useLab((s) => s.wire);
  const selectedId = useLab((s) => s.selectedId);
  const autoForward = useLab((s) => s.autoForward);
  const select = useLab((s) => s.select);
  const deliver = useLab((s) => s.deliver);
  const drop = useLab((s) => s.drop);
  const setAutoForward = useLab((s) => s.setAutoForward);
  const selected = wire.find((p) => p.id === selectedId) ?? wire[wire.length - 1];
  const inspect = selected ? inspectPacket(selected) : null;
  const rows = groupWire(wire);

  return (
    <section className="flex h-full min-h-0 w-full flex-col rounded-xl bg-bg-elevated shadow-[var(--shadow-border)]">
      <header className="flex items-center gap-2 border-b border-border px-4 py-3">
        <Cable className="size-4 text-accent" />
        <div>
          <h2 className="text-sm font-medium text-fg">Session wire</h2>
          <p className="font-mono text-xs text-muted">caller-supplied transport</p>
        </div>
        <label className="ml-auto flex h-11 items-center gap-2 font-mono text-xs text-muted">
          <input
            type="checkbox"
            className="size-4 accent-accent"
            checked={autoForward}
            onChange={(e) => setAutoForward(e.target.checked)}
          />
          auto-forward
        </label>
      </header>

      <ol className="flex max-h-56 flex-col gap-1 overflow-y-auto p-3 lg:max-h-none lg:flex-1">
        {wire.length === 0 ? (
          <li className="m-auto px-2 py-8 text-center text-sm text-muted">
            Packets appear here. Drop one to exercise erasure coding.
          </li>
        ) : (
          rows.map((row) =>
            row.type === "burst" ? (
              <BurstRow
                key={row.packets[0]!.id}
                row={row}
                selectedId={selectedId}
                onSelect={select}
              />
            ) : (
              <PacketRow
                key={row.pkt.id}
                pkt={row.pkt}
                selected={selectedId === row.pkt.id}
                onSelect={select}
                onDeliver={deliver}
                onDrop={drop}
              />
            ),
          )
        )}
      </ol>

      <div className="border-t border-border p-3">
        <p className="mb-2 font-mono text-xs text-subtle">inspector</p>
        {inspect ? (
          <pre className="max-h-40 overflow-auto rounded-md bg-bg p-3 font-mono text-xs leading-relaxed text-muted">
            {inspect.handshake
              ? `handshake ${inspect.kind}\nlen ${inspect.len} B\nfp  ${inspect.fp}\n${wrapHex(inspect.hex)}`
              : `n=${inspect.header.n} pn=${inspect.header.pn}\ndh  ${inspect.header.dhFp}\nspqr ${inspect.header.spqrType} epoch ${inspect.header.spqrEpoch} idx ${inspect.header.spqrIdx}/${inspect.header.spqrTotal}\ninstall ${inspect.header.installEpoch}\n${wrapHex(inspect.hex)}`}
          </pre>
        ) : (
          <p className="text-sm text-muted">No frames yet.</p>
        )}
      </div>
    </section>
  );
}

function PacketRow({
  pkt,
  selected,
  onSelect,
  onDeliver,
  onDrop,
}: {
  pkt: WirePacket;
  selected: boolean;
  onSelect: (id: string) => void;
  onDeliver: (id: string) => void;
  onDrop: (id: string) => void;
}) {
  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(pkt.id)}
        className={cn(
          "flex w-full items-start gap-2 rounded-md px-2.5 py-2 text-left transition-colors duration-150",
          selected ? "bg-bg-subtle" : "hover:bg-bg-subtle/60",
        )}
      >
        <span
          className={cn(
            "mt-1 font-mono text-xs",
            pkt.from === "alpha" ? "text-accent" : "text-muted",
          )}
        >
          {pkt.from === "alpha" ? "A→" : "B→"}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block font-mono text-xs text-fg">
            {pkt.control ? "spqr" : pkt.kind}
          </span>
          <span className="block truncate font-mono text-xs text-subtle">{pkt.note}</span>
        </span>
        <Badge
          tone={
            pkt.status === "delivered"
              ? "ok"
              : pkt.status === "dropped"
                ? "danger"
                : "warn"
          }
        >
          {pkt.status}
        </Badge>
      </button>
      {pkt.status === "queued" ? (
        <div className="mb-1 ml-8 flex gap-1">
          <Button variant="ghost" size="sm" onClick={() => onDeliver(pkt.id)}>
            Deliver
          </Button>
          <Button variant="ghost" size="sm" onClick={() => onDrop(pkt.id)}>
            Drop
          </Button>
        </div>
      ) : null}
    </li>
  );
}

function BurstRow({
  row,
  selectedId,
  onSelect,
}: {
  row: Extract<WireRow, { type: "burst" }>;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const last = row.packets[row.packets.length - 1]!;
  const selected = row.packets.some((p) => p.id === selectedId);
  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(last.id)}
        className={cn(
          "flex w-full items-start gap-2 rounded-md px-2.5 py-2 text-left transition-colors duration-150",
          selected ? "bg-bg-subtle" : "hover:bg-bg-subtle/60",
        )}
      >
        <span
          className={cn(
            "mt-1 font-mono text-xs",
            row.from === "alpha" ? "text-accent" : "text-muted",
          )}
        >
          {row.from === "alpha" ? "A→" : "B→"}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block font-mono text-xs text-fg">spqr burst</span>
          <span className="block truncate font-mono text-xs text-subtle">
            {row.packets.length} empty in-band frames · {last.note}
          </span>
        </span>
        <Badge tone="muted">{row.packets.length}</Badge>
      </button>
    </li>
  );
}

function wrapHex(hex: string): string {
  const h = hex.slice(0, 192);
  const parts = [];
  for (let i = 0; i < h.length; i += 32) parts.push(h.slice(i, i + 32));
  return parts.join("\n") + (hex.length > 192 ? "\n…" : "");
}