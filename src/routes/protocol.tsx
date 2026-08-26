import { createFileRoute } from "@tanstack/react-router";
import { ProtocolPage } from "@/components/lab/protocol-page";

export const Route = createFileRoute("/protocol")({ component: ProtocolPage });
