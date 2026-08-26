import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function shortHex(hex: string, n = 8): string {
  if (!hex) return "—";
  const h = hex.replace(/^0x/i, "");
  if (h.length <= n) return h;
  return `${h.slice(0, n)}…`;
}

export function bytesLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}
