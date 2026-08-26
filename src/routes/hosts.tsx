import { createFileRoute } from "@tanstack/react-router";
import { HostsPage } from "@/components/lab/hosts-page";

export const Route = createFileRoute("/hosts")({ component: HostsPage });
