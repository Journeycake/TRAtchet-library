import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { cn } from "@/lib/utils";

const ITEMS = [
  { to: "/", id: "lab", label: "Lab" },
  { to: "/hosts", id: "hosts", label: "Hosts" },
  { to: "/protocol", id: "protocol", label: "Protocol" },
] as const;

export function LabNav({
  current,
  actions,
}: {
  current: (typeof ITEMS)[number]["id"];
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-center gap-3 border-b border-border bg-bg/90 px-4 py-3 backdrop-blur-sm lg:px-6">
      <Link to="/" className="flex items-baseline gap-1.5">
        <span className="font-sans text-lg font-medium tracking-tight text-fg">
          TR<span className="text-accent">atchet</span>
        </span>
      </Link>
      <nav className="flex items-center gap-1">
        {ITEMS.map((item) => (
          <Link
            key={item.id}
            to={item.to}
            className={cn(
              "flex h-11 items-center rounded-md px-3 font-mono text-xs",
              current === item.id ? "text-accent" : "text-muted hover:text-fg",
            )}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      {actions ? (
        <div className="ml-auto flex flex-wrap items-center gap-1.5">{actions}</div>
      ) : null}
    </header>
  );
}
