import Link from "next/link";
import { notFound } from "next/navigation";
import { getProxyByKey, type ProxyEvent } from "@/lib/airlock";
import { requirePagePermission } from "@/lib/auth";
import type { ReactNode } from "react";
import { ProxyRefresh } from "../proxy-refresh";

type ProxyDetailPageProps = {
  params: Promise<{
    proxyKey: string;
  }>;
  searchParams: Promise<{
    cursor?: string;
  }>;
};

export default async function ProxyDetailPage({
  params,
  searchParams,
}: ProxyDetailPageProps) {
  await requirePagePermission("admin:read");

  const { proxyKey } = await params;
  const { cursor } = await searchParams;
  const result = await getProxyByKey(proxyKey, cursor);

  if (!result.ok) {
    if (result.error === "Proxy not found" || result.error === "Invalid proxy key") {
      notFound();
    }
    return (
      <main className="px-6 pb-12 pt-9 text-slate-950 sm:px-8 lg:px-[72px]">
        <section className="mx-auto max-w-6xl">
          <div className="border border-rose-200 bg-rose-50 px-5 py-4 text-sm text-rose-950">
            {result.error}
          </div>
        </section>
      </main>
    );
  }

  const {
    proxy,
    source,
    controlPlane,
    events,
    eventSource,
    nextEventCursor,
  } = result.data;
  const decisions = proxy.decisions ?? {
    allowed: 0,
    denied: 0,
    proxyError: 0,
  };
  const totalDecisions =
    decisions.allowed + decisions.denied + decisions.proxyError;

  return (
    <main className="px-6 pb-12 pt-9 text-slate-950 sm:px-8 lg:px-[72px]">
      <ProxyRefresh intervalMs={2000} />
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        <header className="border-b border-slate-200 pb-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-wide text-teal-700">
                Proxy
              </p>
              <h1 className="mt-2 break-all text-3xl font-semibold">
                {proxy.id}
              </h1>
              <p className="mt-2 font-mono text-xs text-slate-500">
                {proxy.workloadIdentity || "unassigned"}
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <Metric label="Allowed" value={decisions.allowed} tone="allowed" />
              <Metric label="Denied" value={decisions.denied} tone="denied" />
              <Metric
                label="Proxy error"
                value={decisions.proxyError}
                tone="proxyError"
              />
              <Metric label="Total" value={totalDecisions} />
            </div>
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_24rem]">
          <div className="flex flex-col gap-6">
            <div className="overflow-hidden border border-slate-200 bg-white">
              <div className="border-b border-slate-200 px-4 py-3">
                <h2 className="text-sm font-semibold text-slate-800">
                  Instances
                </h2>
              </div>
              {proxy.instances.length === 0 ? (
                <div className="px-4 py-10 text-sm text-slate-500">
                  No proxy instances have reported heartbeats.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                    <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                      <tr>
                        <TableHeader>Instance</TableHeader>
                        <TableHeader>Pod</TableHeader>
                        <TableHeader>Heartbeat</TableHeader>
                        <TableHeader>Status</TableHeader>
                      </tr>
                    </thead>
                    <tbody>
                      {proxy.instances.map((instance) => (
                        <tr key={instance.id}>
                          <td className="border-t border-slate-100 px-4 py-4 align-top font-mono text-xs text-slate-800">
                            {instance.id}
                          </td>
                          <td className="border-t border-slate-100 px-4 py-4 align-top">
                            {[instance.podNamespace, instance.podName]
                              .filter(Boolean)
                              .join("/") || "-"}
                          </td>
                          <td className="border-t border-slate-100 px-4 py-4 align-top">
                            <div>{formatDate(instance.lastHeartbeatAt)}</div>
                            <div className="mt-1 text-xs text-slate-500">
                              {instance.heartbeatInterval || "-"}
                            </div>
                          </td>
                          <td className="border-t border-slate-100 px-4 py-4 align-top">
                            <span className="inline-flex border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-slate-700">
                              {instance.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="overflow-hidden border border-slate-200 bg-white">
              <div className="border-b border-slate-200 px-4 py-3">
                <h2 className="text-sm font-semibold text-slate-800">
                  Decision counters
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <TableHeader>Decision</TableHeader>
                      <TableHeader>Count</TableHeader>
                      <TableHeader>Share</TableHeader>
                    </tr>
                  </thead>
                  <tbody>
                    <DecisionRow
                      label="Allowed"
                      value={decisions.allowed}
                      total={totalDecisions}
                      tone="allowed"
                    />
                    <DecisionRow
                      label="Denied"
                      value={decisions.denied}
                      total={totalDecisions}
                      tone="denied"
                    />
                    <DecisionRow
                      label="Proxy error"
                      value={decisions.proxyError}
                      total={totalDecisions}
                      tone="proxyError"
                    />
                  </tbody>
                </table>
              </div>
            </div>

            <div className="overflow-hidden border border-slate-200 bg-white">
              <div className="border-b border-slate-200 px-4 py-3">
                <h2 className="text-sm font-semibold text-slate-800">
                  Recent events
                </h2>
              </div>
              {events.length === 0 ? (
                <div className="px-4 py-10 text-sm text-slate-500">
                  No denied or error events have been reported by this proxy yet.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                    <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                      <tr>
                        <TableHeader>Time</TableHeader>
                        <TableHeader>Type</TableHeader>
                        <TableHeader>Count</TableHeader>
                        <TableHeader>Event</TableHeader>
                      </tr>
                    </thead>
                    <tbody>
                      {events.map((event) => (
                        <tr key={event.id}>
                          <td className="whitespace-nowrap border-t border-slate-100 px-4 py-4 align-top text-xs text-slate-600">
                            {formatDate(event.observedAt)}
                          </td>
                          <td className="border-t border-slate-100 px-4 py-4 align-top">
                            <span className={toneClass(eventTone(event.type))}>
                              {eventLabel(event.type)}
                            </span>
                          </td>
                          <td className="border-t border-slate-100 px-4 py-4 align-top tabular-nums">
                            {event.count || 1}
                          </td>
                          <td className="border-t border-slate-100 px-4 py-4 align-top font-mono text-xs text-slate-800">
                            {eventSummary(event)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 text-sm">
                <Link
                  href={`/proxies/${proxyKey}`}
                  className="font-medium text-teal-700 hover:underline"
                >
                  Latest
                </Link>
                {nextEventCursor ? (
                  <Link
                    href={`/proxies/${proxyKey}?cursor=${encodeURIComponent(
                      nextEventCursor,
                    )}`}
                    className="font-medium text-teal-700 hover:underline"
                  >
                    Older
                  </Link>
                ) : (
                  <span className="text-slate-400">Older</span>
                )}
              </div>
            </div>
          </div>

          <aside className="flex flex-col gap-4">
            <InfoPanel title="Status">
              <InfoRow label="State" value={proxy.status} />
              <InfoRow
                label="Instances"
                value={`${proxy.activeInstances}/${proxy.instanceCount}`}
              />
              <InfoRow
                label="Last heartbeat"
                value={formatDate(proxy.lastHeartbeatAt)}
              />
              <InfoRow
                label="Last decision"
                value={formatDate(proxy.lastDecisionAt)}
              />
            </InfoPanel>

            <InfoPanel title="Workload policy">
              <InfoRow label="Name" value={proxy.workloadName || "-"} />
              <InfoRow label="Version" value={proxy.effectivePolicyVersion || "-"} />
              <InfoRow
                label="Last policy fetch"
                value={formatDate(proxy.lastPolicyFetchAt)}
              />
            </InfoPanel>

            <InfoPanel title="Runtime">
              <InfoRow label="Mode" value={proxy.proxyType || "-"} />
              <InfoRow label="Source" value={source} />
              <InfoRow label="Event source" value={eventSource} />
              <InfoRow label="Control plane" value={controlPlane} mono />
            </InfoPanel>
          </aside>
        </section>
      </section>
    </main>
  );
}

function DecisionRow({
  label,
  value,
  total,
  tone,
}: {
  label: string;
  value: number;
  total: number;
  tone: "allowed" | "denied" | "proxyError";
}) {
  const share = total === 0 ? 0 : Math.round((value / total) * 100);
  return (
    <tr>
      <td className="border-t border-slate-100 px-4 py-4 align-top">
        <span className={toneClass(tone)}>{label}</span>
      </td>
      <td className="border-t border-slate-100 px-4 py-4 align-top text-2xl font-semibold tabular-nums">
        {value}
      </td>
      <td className="border-t border-slate-100 px-4 py-4 align-top tabular-nums">
        {share}%
      </td>
    </tr>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: ReactNode;
  tone?: "allowed" | "denied" | "proxyError";
}) {
  return (
    <div className="min-w-24 border border-slate-200 bg-white px-4 py-3">
      <div className={`text-2xl font-semibold tabular-nums ${toneText(tone)}`}>
        {value}
      </div>
      <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
    </div>
  );
}

function InfoPanel({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-800">{title}</h2>
      </div>
      <div className="divide-y divide-slate-100">{children}</div>
    </section>
  );
}

function InfoRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid gap-1 px-4 py-3 text-sm">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div
        className={
          mono
            ? "break-all font-mono text-xs text-slate-800"
            : "break-words text-slate-900"
        }
      >
        {value}
      </div>
    </div>
  );
}

function TableHeader({ children }: { children: ReactNode }) {
  return (
    <th className="border-b border-slate-200 px-4 py-3 font-semibold">
      {children}
    </th>
  );
}

function formatDate(value?: string) {
  if (!value) {
    return "-";
  }
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function toneClass(tone: "allowed" | "denied" | "proxyError") {
  return `font-medium ${toneText(tone)}`;
}

function toneText(tone?: "allowed" | "denied" | "proxyError") {
  switch (tone) {
    case "allowed":
      return "text-emerald-700";
    case "denied":
      return "text-rose-700";
    case "proxyError":
      return "text-amber-700";
    default:
      return "text-slate-950";
  }
}

function eventTone(type: ProxyEvent["type"]) {
  return type === "egress.denied" || type === "event.suppressed"
    ? "denied"
    : "proxyError";
}

function eventLabel(type: ProxyEvent["type"]) {
  switch (type) {
    case "egress.denied":
      return "Denied";
    case "proxy.error":
      return "Proxy error";
    case "policy.fetch_failed":
      return "Policy fetch";
    case "secret.resolve_failed":
      return "Secret";
    case "control_plane.auth_failed":
      return "Auth";
    case "event.suppressed":
      return "Suppressed";
  }
}

function eventSummary(event: ProxyEvent) {
  const parts = [
    event.message,
    event.reason ? `reason=${event.reason}` : "",
    event.destination
      ? `destination=${destinationText(event.destination)}`
      : "",
  ].filter(Boolean);
  return parts.join(" ");
}

function destinationText(destination: NonNullable<ProxyEvent["destination"]>) {
  const scheme = destination.scheme ? `${destination.scheme}://` : "";
  const port = destination.port ? `:${destination.port}` : "";
  return `${scheme}${destination.host}${port}`;
}
