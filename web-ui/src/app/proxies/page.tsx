import Link from "next/link";
import { listProxies } from "@/lib/airlock";
import type { ReactNode } from "react";

export default async function ProxiesPage() {
  const result = await listProxies();

  if (!result.ok) {
    return (
      <main className="min-h-screen px-6 py-8 text-slate-950 sm:px-8">
        <section className="mx-auto max-w-6xl">
          <Link href="/" className="text-sm font-medium text-teal-700 hover:underline">
            Policies
          </Link>
          <div className="mt-6 border border-rose-200 bg-rose-50 px-5 py-4 text-sm text-rose-950">
            {result.error}
          </div>
        </section>
      </main>
    );
  }

  const proxies = result.data.proxies;
  const active = proxies.filter((proxy) => proxy.status === "active").length;

  return (
    <main className="min-h-screen px-6 py-8 text-slate-950 sm:px-8">
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        <header className="flex flex-col gap-5 border-b border-slate-200 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <Link
              href="/"
              className="text-sm font-medium text-teal-700 hover:underline"
            >
              Policies
            </Link>
            <p className="mt-5 text-sm font-semibold uppercase tracking-wide text-teal-700">
              Airlock Console
            </p>
            <h1 className="mt-2 text-3xl font-semibold">Proxies</h1>
          </div>
          <div className="grid grid-cols-3 gap-3 text-sm">
            <Metric label="Active" value={active} />
            <Metric label="Known" value={proxies.length} />
            <Metric label="Source" value={result.data.source} compact />
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
                    <TableHeader>Policy</TableHeader>
                    <TableHeader>Mode</TableHeader>
                    <TableHeader>Last policy fetch</TableHeader>
                    <TableHeader>Last heartbeat</TableHeader>
                    <TableHeader>Status</TableHeader>
                  </tr>
                </thead>
                <tbody>
                  {proxies.map((proxy) => (
                    <tr key={proxy.id}>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <div className="font-medium text-slate-950">
                          {proxy.id}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          {[proxy.podNamespace, proxy.podName]
                            .filter(Boolean)
                            .join("/") || "-"}
                        </div>
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top font-mono text-xs text-slate-800">
                        {proxy.workloadIdentity || "-"}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <div className="font-medium text-slate-900">
                          {proxy.policyName || "-"}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          {proxy.policyVersion || "-"}
                        </div>
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {proxy.proxyType || "-"}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {formatDate(proxy.lastPolicyFetchAt)}
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
