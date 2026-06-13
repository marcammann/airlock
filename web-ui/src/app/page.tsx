import Link from "next/link";
import { destinationLabel, listPolicies, policyKey } from "@/lib/airlock";
import type { ReactNode } from "react";

export default async function Home() {
  const result = await listPolicies();

  if (!result.ok) {
    return (
      <main className="min-h-screen px-6 py-8 text-slate-950 sm:px-8">
        <section className="mx-auto max-w-6xl">
          <div className="mb-8 flex flex-col gap-2">
            <p className="text-sm font-semibold uppercase tracking-wide text-rose-700">
              Airlock Console
            </p>
            <h1 className="text-3xl font-semibold">Policies</h1>
          </div>
          <div className="border border-rose-200 bg-rose-50 px-5 py-4 text-sm text-rose-950">
            {result.error}
          </div>
        </section>
      </main>
    );
  }

  const policies = result.data.policies;
  const totalEgress = policies.reduce(
    (total, policy) => total + policy.egressCount,
    0,
  );
  const totalRewrites = policies.reduce(
    (total, policy) => total + policy.rewriteCount,
    0,
  );

  return (
    <main className="min-h-screen px-6 py-8 text-slate-950 sm:px-8">
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        <header className="flex flex-col gap-5 border-b border-slate-200 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-teal-700">
              Airlock Console
            </p>
            <h1 className="mt-2 text-3xl font-semibold">Policies</h1>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="grid grid-cols-3 gap-3 text-sm">
              <Metric label="Policies" value={policies.length} />
              <Metric label="Egress" value={totalEgress} />
              <Metric label="Rewrites" value={totalRewrites} />
            </div>
            <Link
              href="/proxies"
              className="inline-flex h-10 items-center justify-center border border-slate-300 bg-white px-4 text-sm font-medium text-slate-800 hover:bg-slate-50"
            >
              Proxies
            </Link>
          </div>
        </header>

        <section className="overflow-hidden border border-slate-200 bg-white">
          <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
            <h2 className="text-sm font-semibold text-slate-800">
              Available policies
            </h2>
            <span className="text-xs text-slate-500">
              {result.data.source}
            </span>
          </div>

          {policies.length === 0 ? (
            <div className="px-4 py-10 text-sm text-slate-500">
              No policies are currently loaded.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <TableHeader>Policy</TableHeader>
                    <TableHeader>Workload</TableHeader>
                    <TableHeader>Allowed egress</TableHeader>
                    <TableHeader>Rewrites</TableHeader>
                    <TableHeader>Provider</TableHeader>
                    <TableHeader>Managed</TableHeader>
                  </tr>
                </thead>
                <tbody>
                  {policies.map((policy) => (
                    <tr
                      key={`${policy.workload.spiffeId}:${policy.name}`}
                      className="border-b border-slate-100"
                    >
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <Link
                          href={`/policies/${policyKey(policy)}`}
                          className="font-medium text-slate-950 underline-offset-4 hover:underline"
                        >
                          {policy.name}
                        </Link>
                        <div className="mt-1 text-xs text-slate-500">
                          {policy.version}
                        </div>
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <div className="font-mono text-xs text-slate-800">
                          {policy.workload.spiffeId || "unassigned"}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-600">
                          <Badge>{policy.workload.namespace || "namespace -"}</Badge>
                          <Badge>
                            {policy.workload.serviceAccount || "service account -"}
                          </Badge>
                        </div>
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <div className="flex flex-col gap-2">
                          {policy.egress.map((egress) => (
                            <div key={egress.name}>
                              <div className="font-medium text-slate-900">
                                {egress.name}
                              </div>
                              <div className="font-mono text-xs text-slate-500">
                                {destinationLabel(egress)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {policy.rewriteCount}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        {policy.secretProvider?.provider ? (
                          <Badge>{policy.secretProvider.provider}</Badge>
                        ) : (
                          <span className="text-slate-400">none</span>
                        )}
                      </td>
                      <td className="border-t border-slate-100 px-4 py-4 align-top">
                        <div className="text-slate-800">{policy.managedBy}</div>
                        <div className="mt-1 text-xs text-slate-500">
                          {policy.source}
                        </div>
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

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="min-w-24 border border-slate-200 bg-white px-4 py-3">
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
    </div>
  );
}

function Badge({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-slate-700">
      {children}
    </span>
  );
}

function TableHeader({ children }: { children: ReactNode }) {
  return (
    <th className="border-b border-slate-200 px-4 py-3 font-semibold">
      {children}
    </th>
  );
}
