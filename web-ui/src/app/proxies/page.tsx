import Link from "next/link";
import { listProxies, proxyKey } from "@/lib/airlock";
import { requirePagePermission } from "@/lib/auth";
import type { ReactNode } from "react";
import { ProxyRefresh } from "./proxy-refresh";

export default async function ProxiesPage() {
  await requirePagePermission("admin:read");

  const result = await listProxies();

  if (!result.ok) {
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

  const proxies = result.data.proxies;
  const active = proxies.filter((proxy) => proxy.status === "active").length;
  const allowed = proxies.reduce(
    (total, proxy) => total + (proxy.decisions?.allowed ?? 0),
    0,
  );

  return (
    <main className="px-6 pb-12 pt-9 text-slate-950 sm:px-8 lg:px-[72px]">
      <ProxyRefresh intervalMs={2000} />
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        <header className="flex flex-col gap-5 border-b border-slate-200 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="text-3xl font-semibold">Proxies</h1>
          </div>
          <div className="grid grid-cols-3 gap-3 text-sm">
            <Metric label="Active" value={active} />
            <Metric label="Known" value={proxies.length} />
            <Metric label="Allowed" value={allowed} />
          </div>
        </header>

        <section className="overflow-hidden border border-slate-200 bg-white">
          <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
            <h2 className="text-sm font-semibold text-slate-800">
              Proxy inventory
            </h2>
            <span className="text-xs text-slate-500">
              {result.data.controlPlane}
            </span>
          </div>

          {proxies.length === 0 ? (
            <div className="grid gap-2 px-4 py-10 text-sm text-slate-600">
              <div className="font-medium text-slate-900">
                No proxy status records are available.
              </div>
              <div>
                The control plane is not receiving proxy heartbeats yet.
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <TableHeader>Proxy</TableHeader>
                    <TableHeader>Workload</TableHeader>
                    <TableHeader>Workload policy</TableHeader>
                    <TableHeader>Mode</TableHeader>
                    <TableHeader>Instances</TableHeader>
                    <TableHeader>Decisions</TableHeader>
                    <TableHeader>Last decision</TableHeader>
                    <TableHeader>Last heartbeat</TableHeader>
                    <TableHeader>Status</TableHeader>
                  </tr>
                </thead>
                <tbody>
                  {proxies.map((proxy) => (
                    <tr key={proxy.id}>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <Link
                          href={`/proxies/${proxyKey(proxy)}`}
                          className="font-medium text-slate-950 underline-offset-4 hover:underline"
                        >
                          {proxy.id}
                        </Link>
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top font-mono text-xs text-slate-800">
                        {proxy.workloadIdentity || "-"}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <div className="font-medium text-slate-900">
                          {proxy.workloadName || "-"}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          {proxy.effectivePolicyVersion || "-"}
                        </div>
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {proxy.proxyType || "-"}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {proxy.activeInstances}/{proxy.instanceCount}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <DecisionCounts proxy={proxy} />
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {formatDate(proxy.lastDecisionAt)}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {formatDate(proxy.lastHeartbeatAt)}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <span className="inline-flex border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-slate-700">
                          {proxy.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}

function DecisionCounts({
  proxy,
}: {
  proxy: {
    decisions?: {
      allowed: number;
      denied: number;
      proxyError: number;
    };
  };
}) {
  const decisions = proxy.decisions ?? {
    allowed: 0,
    denied: 0,
    proxyError: 0,
  };

  return (
    <div className="grid gap-1 text-xs text-slate-600">
      <div>
        <span className="font-medium text-emerald-700 tabular-nums">
          {decisions.allowed}
        </span>{" "}
        allowed
      </div>
      <div>
        <span className="font-medium text-rose-700 tabular-nums">
          {decisions.denied}
        </span>{" "}
        denied
      </div>
      <div>
        <span className="font-medium text-amber-700 tabular-nums">
          {decisions.proxyError}
        </span>{" "}
        proxy error
      </div>
    </div>
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

function Metric({
  label,
  value,
  compact = false,
}: {
  label: string;
  value: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className="min-w-24 border border-slate-200 bg-white px-4 py-3">
      <div
        className={
          compact
            ? "max-w-36 truncate text-sm font-semibold"
            : "text-2xl font-semibold tabular-nums"
        }
      >
        {value}
      </div>
      <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
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
