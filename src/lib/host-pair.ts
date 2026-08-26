import { createServerFn } from "@tanstack/react-start";
import type { HostPairResult, HostTransport } from "@/lib/tratchet/host-types.ts";

export type { HostPairEvent, HostPairResult, HostTransport } from "@/lib/tratchet/host-types.ts";

export const runLinuxHostPair = createServerFn({ method: "POST" })
  .validator((input: { transport: HostTransport; flushEpoch: boolean }) => {
    const transport = input?.transport;
    if (transport !== "tcp" && transport !== "unix") {
      throw new Error("transport must be tcp or unix");
    }
    return { transport, flushEpoch: Boolean(input.flushEpoch) };
  })
  .handler(async ({ data }): Promise<HostPairResult> => {
    const { runHostPair } = await import("@/lib/tratchet/node-host.ts");
    return runHostPair(data);
  });
