"use client";

import { Play, RotateCcw, Zap } from "lucide-react";
import { HostPanel } from "@/components/lab/host-panel";
import { LabNav } from "@/components/lab/lab-nav";
import { StatusStrip } from "@/components/lab/status-strip";
import { WirePanel } from "@/components/lab/wire-panel";
import { Button } from "@/components/ui/button";
import { useLab, type MobileTab } from "@/lib/lab-store";
import { cn, shortHex } from "@/lib/utils";

export function LabApp() {
  const mobileTab = useLab((s) => s.mobileTab);
  const setMobileTab = useLab((s) => s.setMobileTab);
  const reset = useLab((s) => s.reset);
  const runDemo = useLab((s) => s.runDemo);
  const completePqEpoch = useLab((s) => s.completePqEpoch);
  const demoRunning = useLab((s) => s.demoRunning);
  const error = useLab((s) => s.error);
  const leakedFp = useLab((s) => s.leakedFp);
  const epochNote = useLab((s) => s.epochNote);
  const alpha = useLab((s) => s.alpha);
  const ready = alpha.phase === "established";

  return (
    <div className="lab-grid lab-shell bg-bg text-fg">
      <LabNav
        current="lab"
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => void runDemo()}
              disabled={demoRunning}
            >
              <Play className="size-3.5" />
              Run demo
            </Button>
            <Button variant="ghost" size="sm" onClick={completePqEpoch} disabled={!ready}>
              <Zap className="size-3.5" />
              Complete epoch
            </Button>
            <Button variant="ghost" size="sm" onClick={reset}>
              <RotateCcw className="size-3.5" />
              Reset
            </Button>
          </>
        }
      />

      <StatusStrip />

      {error ? (
        <div className="border-b border-danger/30 bg-danger/10 px-4 py-2 font-mono text-sm text-danger">
          {error}
        </div>
      ) : null}
      {leakedFp ? (
        <div className="border-b border-warn/30 bg-warn/10 px-4 py-2 text-sm text-warn">
          Simulated leak of last hybrid message key{" "}
          <span className="font-mono">{shortHex(leakedFp, 12)}</span>. Previous
          messages used different keys (forward secrecy). A later DH + PQ epoch
          heals the session (post-compromise security).
        </div>
      ) : null}
      {epochNote ? (
        <div className="border-b border-border bg-bg-elevated px-4 py-2 text-sm text-muted">
          {epochNote}
        </div>
      ) : null}

      <div className="flex gap-1 border-b border-border px-2 py-1 lg:hidden">
        {(["alpha", "wire", "bravo"] as MobileTab[]).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setMobileTab(tab)}
            className={cn(
              "h-11 flex-1 rounded-md font-mono text-xs capitalize",
              mobileTab === tab ? "bg-bg-subtle text-fg" : "text-muted",
            )}
          >
            {tab === "alpha" ? "Alpha" : tab === "bravo" ? "Bravo" : "Wire"}
          </button>
        ))}
      </div>

      <main className="lab-main mx-auto w-full max-w-7xl gap-3 p-3 lg:gap-4 lg:p-4">
        <div
          className={cn(
            "min-h-0 overflow-hidden",
            mobileTab === "alpha" ? "flex h-full" : "hidden lg:flex",
          )}
        >
          <HostPanel id="alpha" />
        </div>
        <div
          className={cn(
            "min-h-0 overflow-hidden",
            mobileTab === "wire" ? "flex h-full" : "hidden lg:flex",
          )}
        >
          <WirePanel />
        </div>
        <div
          className={cn(
            "min-h-0 overflow-hidden",
            mobileTab === "bravo" ? "flex h-full" : "hidden lg:flex",
          )}
        >
          <HostPanel id="bravo" />
        </div>
      </main>
    </div>
  );
}
