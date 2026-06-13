import Link from "next/link";
import { notFound } from "next/navigation";
import { destinationLabel, getPolicyByKey } from "@/lib/airlock";
import type { ReactNode } from "react";

type PolicyDetailPageProps = {
  params: Promise<{
    policyKey: string;
  }>;
};

export default async function PolicyDetailPage({
  params,
}: PolicyDetailPageProps) {
  const { policyKey } = await params;
  const result = await getPolicyByKey(policyKey);

  if (!result.ok) {
    if (result.error === "Policy not found" || result.error === "Invalid policy key") {
      notFound();
    }
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

  const { policy, source } = result.data;

  return (
    <main className="min-h-screen px-6 py-8 text-slate-950 sm:px-8">
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        <header className="border-b border-slate-200 pb-6">
          <Link href="/" className="text-sm font-medium text-teal-700 hover:underline">
            Policies
          </Link>
          <div className="mt-5 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-wide text-teal-700">
                Policy
              </p>
              <h1 className="mt-2 text-3xl font-semibold">{policy.name}</h1>
              <p className="mt-2 font-mono text-xs text-slate-500">
                {policy.workload.spiffeId || "unassigned"}
              </p>
            </div>
            <div className="grid grid-cols-3 gap-3 text-sm">
              <Metric label="Egress" value={policy.egressCount} />
              <Metric label="Rewrites" value={policy.rewriteCount} />
              <Metric label="Version" value={policy.version} />
            </div>
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="overflow-hidden border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-4 py-3">
              <h2 className="text-sm font-semibold text-slate-800">
                Allowed egress
              </h2>
            </div>
            {policy.egress.length === 0 ? (
              <div className="px-4 py-10 text-sm text-slate-500">
                No egress destinations are allowed.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <TableHeader>Name</TableHeader>
                      <TableHeader>Destination</TableHeader>
                      <TableHeader>Rewrites</TableHeader>
                    </tr>
                  </thead>
                  <tbody>
                    {policy.egress.map((egress) => (
                      <tr key={egress.name}>
                        <td className="border-t border-slate-100 px-4 py-4 align-top font-medium text-slate-950">
                          {egress.name}
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top font-mono text-xs text-slate-700">
                          {destinationLabel(egress)}
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top tabular-nums">
                          {egress.rewriteCount}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <aside className="flex flex-col gap-4">
            <InfoPanel title="Workload">
              <InfoRow label="Namespace" value={policy.workload.namespace || "-"} />
              <InfoRow
                label="Service account"
                value={policy.workload.serviceAccount || "-"}
              />
              <InfoRow label="SPIFFE ID" value={policy.workload.spiffeId || "-"} mono />
            </InfoPanel>

            <InfoPanel title="Management">
              <InfoRow label="Managed by" value={policy.managedBy} />
              <InfoRow label="Source" value={policy.source} />
              <InfoRow label="Control plane" value={source} mono />
            </InfoPanel>

            <InfoPanel title="Secrets">
              <InfoRow
                label="Provider"
                value={policy.secretProvider?.provider || "none"}
              />
              <InfoRow label="Rewrite metadata" value="redacted" />
            </InfoPanel>
          </aside>
        </section>
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-24 border border-slate-200 bg-white px-4 py-3">
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
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
